"""Orchestrate finding dedupe, notification email delivery, and audit state."""

import json
import logging
from datetime import timedelta
from pathlib import Path
from typing import ClassVar

from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy.orm import Session

from config import Settings
from defectdojo_client import DefectDojoClient
from email_template import build_ticket_content
from db_models import NotificationDelivery, ProcessingStatus, utc_now
from repositories import (
    NotificationDeliveryRepository,
    ProcessingLogRepository,
    SmtpRateLimiter,
    SmtpRateLimitRepository,
)
from schemas import (
    DefectDojoFinding,
    EmailPayload,
    ProjectEmailMapping,
    ProjectEmailMappingConfig,
    SlaPolicy,
    TicketAction,
)
from smtp_client import SmtpClient, is_transient_smtp_error, retry_delay_seconds
from sla import policy_for_severity

logger = logging.getLogger(__name__)
email_adapter = TypeAdapter(EmailStr)

def missing_ticket_fields(finding: DefectDojoFinding) -> list[str]:
    """Return important fields missing for the detected finding type."""
    missing: list[str] = []
    if not finding.product:
        missing.append("product")
    if not (finding.impact or finding.description):
        missing.append("impact_or_description")
    if not finding.mitigation:
        missing.append("mitigation")

    scanner_type = (finding.scanner_type or "").lower()
    if any(marker in scanner_type for marker in ("dast", "zap", "burp", "acunetix")):
        if not finding.endpoint:
            missing.append("endpoint")
    elif any(marker in scanner_type for marker in ("sast", "semgrep", "sonarqube")):
        if not finding.file_path:
            missing.append("file_path")
    elif any(
        marker in scanner_type
        for marker in ("dependency", "sca", "oss index", "dependency-check")
    ):
        if not (finding.component_name or finding.cve):
            missing.append("component_or_cve")
    elif any(
        marker in scanner_type
        for marker in ("security hub", "guardduty", "aws config", "cloud")
    ):
        if not (finding.resource or finding.aws_account_id):
            missing.append("resource_or_account")
    return missing


class FindingProcessor:
    """Coordinate the complete processing flow for DefectDojo findings."""

    _cached_project_email_mapping: ClassVar[dict[str, ProjectEmailMapping]] = {}

    def __init__(self, settings: Settings, db: Session):
        """Initialize clients, repositories, rate limiting, and product mapping."""
        self.settings = settings
        self.processing_logs = ProcessingLogRepository(db)
        self.notification_deliveries = NotificationDeliveryRepository(db)
        self.rate_limiter = SmtpRateLimiter(
            SmtpRateLimitRepository(db),
            settings.smtp_max_emails_per_minute,
            settings.smtp_max_emails_per_hour,
        )
        self.smtp_client = SmtpClient(settings)
        self.defectdojo_client = DefectDojoClient(settings)
        self.project_email_mapping = dict(self._cached_project_email_mapping)
        self._reload_project_email_mapping()

    def _log_missing_finding_fields(
        self, finding: DefectDojoFinding
    ) -> None:
        """Log optional finding fields that reduce ticket investigation quality."""
        missing_fields = missing_ticket_fields(finding)
        if not missing_fields:
            return

        logger.debug(
            "Finding missing recommended fields before ticket sync",
            extra={
                "finding_id": finding.finding_id,
                "product": finding.product,
                "severity": finding.severity,
                "missing_fields": ",".join(missing_fields),
            },
        )

    def process_scheduler_cycle(self) -> None:
        """Fetch findings, drain queued mail, and process each result."""
        self._reload_project_email_mapping()
        self.process_notification_queue()
        new_finding_count = 0

        try:
            findings = self.defectdojo_client.fetch_active_verified_findings(
                product_names=self._configured_defectdojo_product_names()
            )
        except Exception as error:
            logger.exception(
                "DefectDojo API call failed",
                extra={"error_message": str(error)},
            )
            return

        for finding in findings:
            if self.processing_logs.get_by_finding_id(finding.finding_id) is None:
                new_finding_count += 1
            self.process_finding(finding)

        self.process_notification_queue()
        logger.info(
            "Scheduler cycle completed for current findings",
            extra={
                "total_finding": len(findings),
                "new_finding": new_finding_count,
            },
        )

    def process_finding(self, finding: DefectDojoFinding) -> int:
        """Process one finding through dedupe and the configured delivery mode."""
        sla_policy = policy_for_severity(finding.severity)
        self._log_missing_finding_fields(finding)
        return self._process_claimed_finding(
            finding=finding,
            sla_policy=sla_policy,
        )

    def _process_claimed_finding(
        self,
        *,
        finding: DefectDojoFinding,
        sla_policy: SlaPolicy,
    ) -> int:
        """Process a finding after checking existing processing logs."""
        existing = self.processing_logs.get_by_finding_id(finding.finding_id)
        self.processing_logs.mark_seen(
            finding_id=finding.finding_id,
            priority=sla_policy.priority,
            sla_target=sla_policy.target,
            sla_due_at=sla_policy.due_at,
        )
        if existing and existing.status in (
            ProcessingStatus.SENT, ProcessingStatus.RATE_LIMITED
        ):
            logger.debug(
                "Finding already sent or queued; skipping",
                extra={"finding_id": finding.finding_id, "status": existing.status.value},
            )
            return 0

        ticket_action = TicketAction.CREATE
        project_mapping = self._resolve_project_mapping(finding)
        return self._process_notification_email(
            finding=finding,
            sla_policy=sla_policy,
            ticket_action=ticket_action,
            project_mapping=project_mapping,
        )

    def _process_notification_email(
        self,
        *,
        finding: DefectDojoFinding,
        sla_policy: SlaPolicy,
        ticket_action: TicketAction,
        project_mapping: ProjectEmailMapping | None,
    ) -> int:
        """Queue and send notification emails for the mapped product recipients."""
        to_recipients = self._resolve_notify_to_recipients(project_mapping)
        if not to_recipients:
            self.processing_logs.mark_invalid_recipient(
                finding_id=finding.finding_id,
                error_message="No notification recipients configured for product",
                priority=sla_policy.priority,
                sla_target=sla_policy.target,
                sla_due_at=sla_policy.due_at,
            )
            logger.debug(
                "Notification-only finding skipped because no recipients matched",
                extra={
                    "finding_id": finding.finding_id,
                    "product": finding.product,
                    "severity": finding.severity,
                    "status": ProcessingStatus.INVALID_RECIPIENT.value,
                },
            )
            return 0

        self._enqueue_notification_emails(
            finding=finding,
            sla_policy=sla_policy,
            ticket_action=ticket_action,
            project_mapping=project_mapping,
        )
        audit_payload = self._build_email_payload(
            finding=finding,
            recipient=to_recipients[0],
            cc_recipients=self._resolve_cc_recipients(
                project_mapping,
                to_recipients[0],
            ),
            sla_policy=sla_policy,
            ticket_action=ticket_action,
            project_mapping=project_mapping,
        )
        self.processing_logs.upsert_status(
            finding_id=finding.finding_id,
            status=ProcessingStatus.PENDING,
            email_subject=audit_payload.subject,
            retry_count=0,
        )
        sent_email_count = self.process_notification_queue(finding_id=finding.finding_id)
        return 1 if sent_email_count > 0 else 0

    def _build_email_payload(
        self,
        *,
        finding: DefectDojoFinding,
        recipient: str,
        sla_policy: SlaPolicy,
        ticket_action: TicketAction,
        project_mapping: ProjectEmailMapping | None = None,
        to_recipients: list[str] | None = None,
        cc_recipients: list[str] | None = None,
    ) -> EmailPayload:
        """Build a validated email payload using project routing overrides."""
        content = build_ticket_content(
            finding,
            self.settings.defectdojo_base_url,
            sla_policy=sla_policy,
            ticket_action=ticket_action,
            subject_prefix=(
                project_mapping.subject_prefix if project_mapping else None
            ),
            subject_product=(
                project_mapping.display_name if project_mapping else None
            ),
        )
        return EmailPayload(
            finding_id=content.finding_id,
            recipient_email=recipient,
            to_emails=to_recipients or [],
            cc_emails=cc_recipients or [],
            subject=content.subject,
            body=content.body,
            html_body=content.html_body,
            priority=content.priority,
            sla_target=content.sla_target,
            ticket_action=content.ticket_action,
        )

    def _enqueue_notification_emails(
        self,
        *,
        finding: DefectDojoFinding,
        sla_policy: SlaPolicy,
        ticket_action: TicketAction,
        project_mapping: ProjectEmailMapping | None,
    ) -> None:
        """Persist one independent notification delivery per configured recipient."""
        to_recipients = self._resolve_notify_to_recipients(project_mapping)
        if not to_recipients:
            logger.debug(
                "Notification email skipped because no to_destinations are configured",
                extra={
                    "finding_id": finding.finding_id,
                    "flow_type": "notify_email",
                },
            )
            return

        for recipient in to_recipients:
            payload = self._build_email_payload(
                finding=finding,
                recipient=recipient,
                cc_recipients=self._resolve_cc_recipients(
                    project_mapping,
                    recipient,
                ),
                sla_policy=sla_policy,
                ticket_action=ticket_action,
                project_mapping=project_mapping,
            )
            self.notification_deliveries.enqueue(payload)

    def process_notification_queue(self, finding_id: int | None = None) -> int:
        """Send due deliveries; this service requires a single app replica."""
        sent_count = 0
        for delivery in self.notification_deliveries.get_due(finding_id=finding_id):
            if not self.rate_limiter.quota_available():
                self.notification_deliveries.sync_processing_status(delivery.finding_id)
                logger.warning("Notification queue paused because SMTP quota is active")
                break
            if not self.notification_deliveries.touch_due(
                delivery_id=delivery.id,
            ):
                continue
            if self._deliver_notification(delivery):
                sent_count += 1
        return sent_count

    def _deliver_notification(self, delivery: NotificationDelivery) -> bool:
        """Attempt one notification and persist its next state."""
        payload = EmailPayload(
            finding_id=delivery.finding_id,
            recipient_email=delivery.recipient_email,
            cc_emails=self._parse_stored_email_list(delivery.cc_emails),
            subject=delivery.email_subject,
            body=delivery.email_body,
            ticket_action=TicketAction.CREATE,
        )
        try:
            self.smtp_client.send(payload)
        except Exception as error:
            retry_count = delivery.retry_count + 1
            error_message = str(error)
            if (
                is_transient_smtp_error(error)
                and retry_count < self.settings.smtp_max_attempts
            ):
                self.notification_deliveries.mark_retry(
                    delivery_id=delivery.id,
                    retry_count=retry_count,
                    next_attempt_at=self._next_retry_at(retry_count),
                    error_message=error_message,
                )
            else:
                self.notification_deliveries.mark_failed(
                    delivery_id=delivery.id,
                    retry_count=retry_count,
                    error_message=error_message,
                )
            self.notification_deliveries.sync_processing_status(delivery.finding_id)
            logger.warning(
                "Notification delivery failed",
                extra={
                    "finding_id": delivery.finding_id,
                    "delivery_id": delivery.id,
                    "recipient_email": delivery.recipient_email,
                    "flow_type": "notify_email",
                    "retry_count": retry_count,
                    "error_message": error_message,
                },
            )
            return False

        # SMTP succeeded. Persistence failures must not enter transport retry.
        try:
            self.notification_deliveries.mark_sent(delivery.id)
            self.notification_deliveries.sync_processing_status(delivery.finding_id)
        except Exception:
            logger.error(
                "SMTP accepted email but delivery audit failed; stop cycle and reconcile",
                extra={"finding_id": delivery.finding_id, "delivery_id": delivery.id},
            )
            raise
        logger.info("Notification email sent successfully",
                    extra={"finding_id": delivery.finding_id, "delivery_id": delivery.id})
        return True

    def _next_retry_at(self, attempt_number: int):
        """Calculate when a queued SMTP delivery becomes eligible again."""
        delay = retry_delay_seconds(
            attempt_number=max(attempt_number, 1),
            base_delay_seconds=self.settings.smtp_retry_delay_seconds,
            backoff_multiplier=self.settings.smtp_retry_backoff_multiplier,
        )
        return utc_now() + timedelta(seconds=delay)

    def _parse_stored_email_list(self, value: str | None) -> list[str]:
        """Parse a comma-separated audit value back into validated addresses."""
        if not value:
            return []
        return self._dedupe_email_values(
            [part.strip() for part in value.split(",") if part.strip()]
        )

    def _resolve_project_mapping(
        self, finding: DefectDojoFinding
    ) -> ProjectEmailMapping | None:
        """Resolve the routing entry matching the finding's product name."""
        if not finding.product:
            return None
        return self.project_email_mapping.get(finding.product.strip().lower())

    def _resolve_notify_to_recipients(
        self, project_mapping: ProjectEmailMapping | None
    ) -> list[str]:
        """Return deduplicated primary notification recipients."""
        if not project_mapping:
            return []

        return self._dedupe_email_values(project_mapping.to_destinations)

    def _resolve_cc_recipients(
        self,
        project_mapping: ProjectEmailMapping | None,
        excluded_recipients: str | list[str],
    ) -> list[str]:
        """Return valid Cc addresses excluding the supplied To recipient(s)."""
        if not project_mapping:
            return []

        recipients: list[str] = []
        if isinstance(excluded_recipients, str):
            seen = {excluded_recipients.lower()}
        else:
            seen = {recipient.lower() for recipient in excluded_recipients}
        for destination in project_mapping.cc_destinations:
            valid_destination = self._validate_email(destination)
            if not valid_destination:
                continue
            normalized = valid_destination.lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            recipients.append(valid_destination)
        return recipients

    def _dedupe_email_values(self, values: list[EmailStr] | list[str]) -> list[str]:
        """Validate addresses and remove case-insensitive duplicates."""
        recipients: list[str] = []
        seen: set[str] = set()
        for value in values:
            valid_value = self._validate_email(str(value))
            if not valid_value:
                continue
            normalized = valid_value.lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            recipients.append(valid_value)
        return recipients

    def _validate_email(self, value: str | None) -> str | None:
        """Return a normalized email address or None when invalid."""
        if not value:
            return None
        try:
            return str(email_adapter.validate_python(value))
        except ValidationError:
            return None

    def _load_project_email_mapping(self) -> dict[str, ProjectEmailMapping]:
        """Load file and inline mappings, with inline entries taking precedence."""
        merged: dict[str, ProjectEmailMapping] = {}

        if self.settings.project_email_mapping_file:
            path = Path(self.settings.project_email_mapping_file)
            file_mapping = ProjectEmailMappingConfig.model_validate_json(
                path.read_text(encoding="utf-8")
            )
            for project in file_mapping.projects:
                key, normalized_project = self._normalize_project_mapping(project)
                merged[key] = normalized_project

        if self.settings.project_email_mapping_json:
            raw_mapping = json.loads(self.settings.project_email_mapping_json)
            json_mapping = ProjectEmailMappingConfig.model_validate(raw_mapping)
            for project in json_mapping.projects:
                key, normalized_project = self._normalize_project_mapping(project)
                merged[key] = normalized_project

        return merged

    def _normalize_project_mapping(
        self, project: ProjectEmailMapping
    ) -> tuple[str, ProjectEmailMapping]:
        """Keep legacy product aliases readable while routing by product name."""
        match_product = self._split_mapping_product_name(project.product_name)
        normalized_project = project.model_copy(
            update={
                "product_name": match_product,
                "display_name": project.display_name or (
                    project.product_name.split(":", 1)[1].strip()
                    if ":" in project.product_name else None
                ),
            }
        )
        return match_product.lower(), normalized_project

    def _split_mapping_product_name(self, product_name: str) -> str:
        """Return the DefectDojo product key from a legacy aliased mapping."""
        raw_product_name = product_name.strip()
        if ":" not in raw_product_name:
            return raw_product_name
        return raw_product_name.split(":", 1)[0].strip() or raw_product_name

    def _reload_project_email_mapping(self) -> bool:
        """Reload product mapping and keep the last good config on failure."""
        try:
            mapping = self._load_project_email_mapping()
        except (OSError, ValueError, ValidationError) as error:
            fallback_mapping = self._cached_project_email_mapping
            self.project_email_mapping = dict(fallback_mapping)
            logger.error(
                "Project email mapping reload failed; keeping last good mapping",
                extra={
                    "error_message": str(error),
                    "project_count": len(fallback_mapping),
                },
            )
            return False

        self.project_email_mapping = mapping
        FindingProcessor._cached_project_email_mapping = dict(mapping)
        return True

    def _configured_defectdojo_product_names(self) -> list[str]:
        """Return product names configured for DefectDojo API filtering."""
        return [
            project.product_name
            for project in self.project_email_mapping.values()
            if project.product_name.strip()
        ]
