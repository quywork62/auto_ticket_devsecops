"""Orchestrate finding dedupe, notification email delivery, and audit state."""

import json
import logging
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from pathlib import Path
from typing import ClassVar

from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy.orm import Session

from config import Settings
from dedupe import build_dedupe_key
from defectdojo_client import DefectDojoClient
from email_template import build_ticket_content
from db_models import NotificationDelivery, ProcessingLog, ProcessingStatus, utc_now
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

logger = logging.getLogger(__name__)
email_adapter = TypeAdapter(EmailStr)

SLA_BY_SEVERITY = {
    "critical": ("P1/Critical", timedelta(days=7), "7 days"),
    "high": ("P2/High", timedelta(days=14), "14 days"),
    "medium": ("P3/Medium", timedelta(days=30), "30 days"),
    "low": ("P4/Low", timedelta(days=90), "60 - 90 days"),
    "informational": ("P5/Info", None, "Best effort"),
    "info": ("P5/Info", None, "Best effort"),
}


def policy_for_severity(severity: str) -> SlaPolicy:
    """Return internal priority/SLA metadata for notification email audit."""
    normalized = severity.strip().lower()
    priority, delta, target = SLA_BY_SEVERITY.get(
        normalized, ("P5/Info", None, "Best effort")
    )
    now = datetime.now(timezone.utc)
    return SlaPolicy(
        severity=severity,
        priority=priority,
        target=target,
        due_at=now + delta if delta else None,
    )


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
        self.worker_id = str(uuid4())
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
        self, finding: DefectDojoFinding, dedupe_key: str
    ) -> None:
        """Log optional finding fields that reduce ticket investigation quality."""
        missing_fields = missing_ticket_fields(finding)
        if not missing_fields:
            return

        logger.debug(
            "Finding missing recommended fields before ticket sync",
            extra={
                "finding_id": finding.finding_id,
                "dedupe_key": dedupe_key,
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

    def process_rate_limited_queue(self) -> None:
        """Kept for compatibility; notification retry lives in notification_deliveries."""
        return None

    def process_finding(self, finding: DefectDojoFinding) -> int:
        """Process one finding through dedupe and the configured delivery mode."""
        dedupe_key = build_dedupe_key(finding)
        sla_policy = policy_for_severity(finding.severity)
        self._log_missing_finding_fields(finding, dedupe_key)
        return self._process_claimed_finding(
            finding=finding,
            dedupe_key=dedupe_key,
            sla_policy=sla_policy,
        )

    def _process_claimed_finding(
        self,
        *,
        finding: DefectDojoFinding,
        dedupe_key: str,
        sla_policy: SlaPolicy,
    ) -> int:
        """Process a finding after checking existing processing logs."""
        existing = self.processing_logs.get_by_finding_id(finding.finding_id)
        dedupe_duplicate = self.processing_logs.get_sent_or_queued_by_dedupe_key(
            dedupe_key
        )

        self.processing_logs.mark_seen(
            finding_id=finding.finding_id,
            dedupe_key=dedupe_key,
            priority=sla_policy.priority,
            sla_target=sla_policy.target,
            sla_due_at=sla_policy.due_at,
        )

        duplicate_record = self._select_duplicate_record(existing, dedupe_duplicate)
        if duplicate_record and duplicate_record.status == ProcessingStatus.SENT:
            if not existing or existing.status != ProcessingStatus.SENT:
                self.processing_logs.mark_skipped(
                    finding_id=finding.finding_id,
                    error_message=(
                        "Duplicate issue skipped because dedupe_key already has "
                        f"SENT finding_id={duplicate_record.finding_id}"
                    ),
                    dedupe_key=dedupe_key,
                    priority=sla_policy.priority,
                    sla_target=sla_policy.target,
                    sla_due_at=sla_policy.due_at,
                )
            logger.debug(
                "Duplicate skipped",
                extra={
                    "finding_id": finding.finding_id,
                    "dedupe_key": dedupe_key,
                    "existing_finding_id": duplicate_record.finding_id,
                    "product": finding.product,
                    "severity": finding.severity,
                    "status": ProcessingStatus.SKIPPED.value,
                },
            )
            return 0

        if duplicate_record and duplicate_record.status == ProcessingStatus.RATE_LIMITED:
            logger.debug(
                "Finding already queued due to rate limit",
                extra={
                    "finding_id": finding.finding_id,
                    "dedupe_key": dedupe_key,
                    "status": ProcessingStatus.RATE_LIMITED.value,
                },
            )
            return 0

        ticket_action = TicketAction.CREATE
        project_mapping = self._resolve_project_mapping(finding)
        return self._process_notification_email(
            finding=finding,
            dedupe_key=dedupe_key,
            sla_policy=sla_policy,
            ticket_action=ticket_action,
            project_mapping=project_mapping,
        )

    def _select_duplicate_record(
        self,
        existing: ProcessingLog | None,
        dedupe_duplicate: ProcessingLog | None,
    ) -> ProcessingLog | None:
        """Choose the record that determines whether processing must stop."""
        if existing and existing.status in (
            ProcessingStatus.SENT,
            ProcessingStatus.RATE_LIMITED,
        ):
            return existing
        if dedupe_duplicate:
            return dedupe_duplicate
        return existing

    def _process_notification_email(
        self,
        *,
        finding: DefectDojoFinding,
        dedupe_key: str,
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
                dedupe_key=dedupe_key,
                priority=sla_policy.priority,
                sla_target=sla_policy.target,
                sla_due_at=sla_policy.due_at,
            )
            logger.debug(
                "Notification-only finding skipped because no recipients matched",
                extra={
                    "finding_id": finding.finding_id,
                    "dedupe_key": dedupe_key,
                    "product": finding.product,
                    "severity": finding.severity,
                    "status": ProcessingStatus.INVALID_RECIPIENT.value,
                },
            )
            return 0

        self._enqueue_notification_emails(
            finding=finding,
            dedupe_key=dedupe_key,
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
            dedupe_key=dedupe_key,
            sla_policy=sla_policy,
            ticket_action=ticket_action,
            project_mapping=project_mapping,
        )
        self.processing_logs.upsert_status(
            finding_id=finding.finding_id,
            status=ProcessingStatus.PENDING,
            email_subject=audit_payload.subject,
            retry_count=0,
            dedupe_key=dedupe_key,
        )
        sent_email_count = self.process_notification_queue(finding_id=finding.finding_id)
        return 1 if sent_email_count > 0 else 0

    def _build_email_payload(
        self,
        *,
        finding: DefectDojoFinding,
        recipient: str,
        dedupe_key: str,
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
            dedupe_key=dedupe_key,
            sla_policy=sla_policy,
            ticket_action=ticket_action,
            subject_prefix=(
                project_mapping.subject_prefix if project_mapping else None
            ),
            subject_product_name=(
                project_mapping.subject_product_name if project_mapping else None
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
            dedupe_key=content.dedupe_key,
            priority=content.priority,
            sla_target=content.sla_target,
            ticket_action=content.ticket_action,
        )

    def _enqueue_notification_emails(
        self,
        *,
        finding: DefectDojoFinding,
        dedupe_key: str,
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
                    "dedupe_key": dedupe_key,
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
                dedupe_key=dedupe_key,
                sla_policy=sla_policy,
                ticket_action=ticket_action,
                project_mapping=project_mapping,
            )
            self.notification_deliveries.enqueue(payload)

    def process_notification_queue(self, finding_id: int | None = None) -> int:
        """Send due notification deliveries with database-backed retry leases."""
        sent_count = 0
        for delivery in self.notification_deliveries.get_due(finding_id=finding_id):
            if not self.rate_limiter.quota_available():
                logger.warning("Notification queue paused because SMTP quota is active")
                break
            if not self.notification_deliveries.acquire(
                delivery_id=delivery.id,
                worker_id=self.worker_id,
                lease_seconds=self.settings.notification_lease_ttl_seconds,
            ):
                continue
            if self._deliver_notification(delivery):
                sent_count += 1
        return sent_count

    def _deliver_notification(self, delivery: NotificationDelivery) -> bool:
        """Attempt one leased notification and persist its next state."""
        payload = EmailPayload(
            finding_id=delivery.finding_id,
            recipient_email=delivery.recipient_email,
            cc_emails=self._parse_stored_email_list(delivery.cc_emails),
            subject=delivery.email_subject,
            body=delivery.email_body,
            dedupe_key=delivery.dedupe_key,
            ticket_action=TicketAction.CREATE,
        )
        try:
            self.smtp_client.send(payload)
            self.rate_limiter.record_send(
                finding_id=payload.finding_id,
                recipient_email=str(payload.recipient_email),
                cc_emails=delivery.cc_emails,
                flow_type="notify_email",
            )
            self.notification_deliveries.mark_sent(delivery.id, self.worker_id)
            self.processing_logs.mark_sent(
                finding_id=payload.finding_id,
                email_subject=payload.subject,
                retry_count=delivery.retry_count,
                dedupe_key=payload.dedupe_key,
            )
            logger.info(
                "Notification email sent successfully",
                extra={
                    "finding_id": payload.finding_id,
                    "delivery_id": delivery.id,
                    "dedupe_key": payload.dedupe_key,
                    "recipient_email": str(payload.recipient_email),
                    "cc_emails": delivery.cc_emails,
                    "status": ProcessingStatus.SENT.value,
                },
            )
            return True
        except Exception as error:
            retry_count = delivery.retry_count + 1
            error_message = str(error)
            if (
                is_transient_smtp_error(error)
                and retry_count < self.settings.smtp_max_attempts
            ):
                self.notification_deliveries.mark_retry(
                    delivery_id=delivery.id,
                    worker_id=self.worker_id,
                    retry_count=retry_count,
                    next_attempt_at=self._next_retry_at(retry_count),
                    error_message=error_message,
                )
                self.processing_logs.mark_rate_limited(
                    finding_id=payload.finding_id,
                    email_subject=payload.subject,
                    retry_count=retry_count,
                    error_message=error_message,
                    dedupe_key=payload.dedupe_key,
                )
            else:
                self.notification_deliveries.mark_failed(
                    delivery_id=delivery.id,
                    worker_id=self.worker_id,
                    retry_count=retry_count,
                    error_message=error_message,
                )
                self.processing_logs.mark_failed(
                    finding_id=payload.finding_id,
                    email_subject=payload.subject,
                    retry_count=retry_count,
                    error_message=error_message,
                    dedupe_key=payload.dedupe_key,
                )
            logger.warning(
                "Notification delivery failed",
                extra={
                    "finding_id": delivery.finding_id,
                    "delivery_id": delivery.id,
                    "dedupe_key": delivery.dedupe_key,
                    "recipient_email": delivery.recipient_email,
                    "flow_type": "notify_email",
                    "retry_count": retry_count,
                    "error_message": error_message,
                },
            )
            return False

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

    def _payload_to_recipients(self, payload: EmailPayload) -> list[str]:
        """Return all unique To recipients represented by an email payload."""
        return self._dedupe_email_values(
            [str(payload.recipient_email), *[str(email) for email in payload.to_emails]]
        )

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

    def _format_email_list(self, values: list[EmailStr] | list[str]) -> str | None:
        """Serialize an email list for database audit columns."""
        if not values:
            return None
        return ",".join(str(value) for value in values)

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
            if path.exists():
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
        """Split product_name as defectdojo_product:subject_product when configured."""
        match_product, subject_product_name = self._split_mapping_product_name(
            project.product_name
        )
        normalized_subject_product = (
            project.subject_product_name or subject_product_name
        )
        normalized_project = project.model_copy(
            update={
                "product_name": match_product,
                "subject_product_name": normalized_subject_product,
            }
        )
        return match_product.lower(), normalized_project

    def _split_mapping_product_name(self, product_name: str) -> tuple[str, str | None]:
        """Return DefectDojo product key and optional subject product alias."""
        raw_product_name = product_name.strip()
        if ":" not in raw_product_name:
            return raw_product_name, None

        match_product, subject_product_name = raw_product_name.split(":", 1)
        match_product = match_product.strip()
        subject_product_name = subject_product_name.strip()
        return (
            match_product or raw_product_name,
            subject_product_name or None,
        )

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
