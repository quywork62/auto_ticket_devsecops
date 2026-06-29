"""Orchestrate finding dedupe, ticket delivery, notification, and audit state."""

import json
import logging
from datetime import timedelta
from uuid import uuid4
from pathlib import Path

from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy.orm import Session

from config import Settings
from dedupe import build_dedupe_key
from defectdojo_client import DefectDojoClient
from email_template import build_ticket_content
from manageengine_client import ManageEngineClient
from manageengine_mapper import build_manageengine_payload, policy_for_severity
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
        self.manageengine_client = ManageEngineClient(settings)
        self.project_email_mapping = self._load_project_email_mapping()

    def _log_missing_finding_fields(
        self, finding: DefectDojoFinding, dedupe_key: str
    ) -> None:
        """Log optional finding fields that reduce ticket investigation quality."""
        missing_fields = missing_ticket_fields(finding)
        if not missing_fields:
            return

        logger.warning(
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
        logger.info("Scheduler cycle started")

        if not self._use_manageengine_api():
            self.process_rate_limited_queue()
        self.process_notification_queue()

        try:
            findings = self.defectdojo_client.fetch_active_verified_findings()
        except Exception as error:
            logger.exception(
                "DefectDojo API call failed",
                extra={"error_message": str(error)},
            )
            return

        for finding in findings:
            self.process_finding(finding)

        self.process_notification_queue()
        logger.info("Scheduler cycle ended")

    def process_rate_limited_queue(self) -> None:
        """Retry due ticket emails using payloads persisted in PostgreSQL."""
        queued_items = self.processing_logs.get_rate_limited_items()
        for item in queued_items:
            if not self.rate_limiter.quota_available():
                logger.info("Rate limit still active")
                break

            if (
                not item.recipient_email
                or not item.email_subject
                or not item.email_body
            ):
                self.processing_logs.mark_failed(
                    finding_id=item.finding_id,
                    recipient_email=item.recipient_email,
                    email_subject=item.email_subject,
                    email_body=item.email_body,
                    email_html_body=item.email_html_body,
                    retry_count=item.retry_count,
                    error_message="Queued email payload is incomplete",
                    dedupe_key=item.dedupe_key,
                )
                continue

            payload = EmailPayload(
                finding_id=item.finding_id,
                recipient_email=item.recipient_email,
                subject=item.email_subject,
                body=item.email_body,
                html_body=item.email_html_body,
                dedupe_key=item.dedupe_key,
                priority=item.priority,
                sla_target=item.sla_target,
                ticket_action=TicketAction.CREATE,
            )
            ticket_sent = self._send_with_retry(
                payload,
                flow_type="ticket_email",
                existing_retry_count=item.retry_count,
            )
            if ticket_sent:
                self.process_notification_queue(finding_id=item.finding_id)

    def process_finding(self, finding: DefectDojoFinding) -> None:
        """Process one finding through dedupe and the configured delivery mode."""
        dedupe_key = build_dedupe_key(finding)
        sla_policy = policy_for_severity(finding.severity)
        self._log_missing_finding_fields(finding, dedupe_key)
        self._process_claimed_finding(
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
    ) -> None:
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
            logger.info(
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
            return

        if duplicate_record and duplicate_record.status == ProcessingStatus.RATE_LIMITED:
            logger.info(
                "Finding already queued due to rate limit",
                extra={
                    "finding_id": finding.finding_id,
                    "dedupe_key": dedupe_key,
                    "status": ProcessingStatus.RATE_LIMITED.value,
                },
            )
            return

        ticket_action = TicketAction.CREATE
        project_mapping = self._resolve_project_mapping(finding)
        if self._use_manageengine_api():
            ticket_synced = self._sync_manageengine_ticket(
                finding=finding,
                dedupe_key=dedupe_key,
                sla_policy=sla_policy,
                ticket_action=ticket_action,
            )
            if ticket_synced:
                self._enqueue_notification_emails(
                    finding=finding,
                    dedupe_key=dedupe_key,
                    sla_policy=sla_policy,
                    ticket_action=ticket_action,
                    project_mapping=project_mapping,
                )
                self.process_notification_queue(finding_id=finding.finding_id)
            return

        ticket_mailbox = self._resolve_ticket_mailbox(finding, project_mapping)
        if not ticket_mailbox:
            self.processing_logs.mark_invalid_recipient(
                finding_id=finding.finding_id,
                error_message="No valid recipient from ticket_email or project mapping",
                dedupe_key=dedupe_key,
                priority=sla_policy.priority,
                sla_target=sla_policy.target,
                sla_due_at=sla_policy.due_at,
            )
            logger.info(
                "Invalid recipient",
                extra={
                    "finding_id": finding.finding_id,
                    "dedupe_key": dedupe_key,
                    "product": finding.product,
                    "severity": finding.severity,
                    "status": ProcessingStatus.INVALID_RECIPIENT.value,
                },
            )
            return

        ticket_payload = self._build_email_payload(
            finding=finding,
            recipient=ticket_mailbox,
            dedupe_key=dedupe_key,
            sla_policy=sla_policy,
            ticket_action=ticket_action,
            project_mapping=project_mapping,
        )

        if not self.rate_limiter.quota_available():
            self._enqueue_notification_emails(
                finding=finding,
                dedupe_key=dedupe_key,
                sla_policy=sla_policy,
                ticket_action=ticket_action,
                project_mapping=project_mapping,
            )
            self.processing_logs.mark_rate_limited(
                finding_id=finding.finding_id,
                recipient_email=str(ticket_payload.recipient_email),
                email_subject=ticket_payload.subject,
                email_body=ticket_payload.body,
                email_html_body=ticket_payload.html_body,
                next_attempt_at=self._next_retry_at(1),
                dedupe_key=dedupe_key,
                priority=sla_policy.priority,
                sla_target=sla_policy.target,
                sla_due_at=sla_policy.due_at,
            )
            logger.info(
                "Email queued",
                extra={
                    "finding_id": finding.finding_id,
                    "dedupe_key": dedupe_key,
                    "recipient_email": str(ticket_payload.recipient_email),
                    "status": ProcessingStatus.RATE_LIMITED.value,
                },
            )
            return

        ticket_sent = self._send_with_retry(
            ticket_payload,
            flow_type="ticket_email",
        )
        current_record = self.processing_logs.get_by_finding_id(finding.finding_id)
        if ticket_sent or (
            current_record
            and current_record.status == ProcessingStatus.RATE_LIMITED
        ):
            self._enqueue_notification_emails(
                finding=finding,
                dedupe_key=dedupe_key,
                sla_policy=sla_policy,
                ticket_action=ticket_action,
                project_mapping=project_mapping,
            )
        if ticket_sent:
            self.process_notification_queue(finding_id=finding.finding_id)

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

    def _use_manageengine_api(self) -> bool:
        """Return whether direct ManageEngine API delivery is enabled."""
        return self.settings.manageengine_delivery_mode == "api"

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
        group = (
            project_mapping.group
            if project_mapping and project_mapping.group is not None
            else self.settings.manageengine_default_group
        )
        category = (
            project_mapping.category
            if project_mapping and project_mapping.category is not None
            else self.settings.manageengine_default_category
        )
        subcategory = (
            project_mapping.subcategory
            if project_mapping and project_mapping.subcategory is not None
            else self.settings.manageengine_default_subcategory
        )
        content = build_ticket_content(
            finding,
            self.settings.defectdojo_base_url,
            manageengine_public_url=(
                self.settings.manageengine_public_url
                or self.settings.manageengine_base_url
            ),
            dedupe_key=dedupe_key,
            sla_policy=sla_policy,
            ticket_action=ticket_action,
            group=group,
            category=category,
            subcategory=subcategory,
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

    def _sync_manageengine_ticket(
        self,
        *,
        finding: DefectDojoFinding,
        dedupe_key: str,
        sla_policy: SlaPolicy,
        ticket_action: TicketAction,
    ) -> bool:
        """Create a ManageEngine ticket and persist the API result."""
        payload = build_manageengine_payload(
            finding=finding,
            settings=self.settings,
            dedupe_key=dedupe_key,
            sla_policy=sla_policy,
            ticket_action=ticket_action,
        )
        try:
            result = self.manageengine_client.create_request(payload)
            normalized_status = result.status.strip().upper()
            if normalized_status != "DRY_RUN" and (
                normalized_status not in {"SUCCESS", "SUCCEEDED"}
                or not result.request_id
            ):
                raise ValueError(
                    "ManageEngine ticket was not confirmed: "
                    f"status={result.status!r}, request_id={result.request_id!r}"
                )

            self.processing_logs.mark_ticket_created(
                finding_id=finding.finding_id,
                ticket_id=result.request_id,
                ticket_status=result.status,
                email_subject=payload.subject,
                email_body=payload.description,
                dedupe_key=dedupe_key,
                priority=sla_policy.priority,
                sla_target=sla_policy.target,
                processing_status=(
                    ProcessingStatus.PENDING
                    if normalized_status == "DRY_RUN"
                    else ProcessingStatus.SENT
                ),
            )
            logger.info(
                "ManageEngine ticket synced",
                extra={
                    "finding_id": finding.finding_id,
                    "dedupe_key": dedupe_key,
                    "ticket_id": result.request_id,
                    "ticket_status": result.status,
                },
            )
            return normalized_status != "DRY_RUN"
        except Exception as error:
            self.processing_logs.mark_failed(
                finding_id=finding.finding_id,
                recipient_email=None,
                email_subject=payload.subject,
                email_body=payload.description,
                email_html_body=None,
                retry_count=0,
                error_message=str(error),
                dedupe_key=dedupe_key,
            )
            logger.exception(
                "ManageEngine ticket sync failed",
                extra={
                    "finding_id": finding.finding_id,
                    "dedupe_key": dedupe_key,
                    "error_message": str(error),
                },
            )
            return False

    def _send_with_retry(
        self,
        payload: EmailPayload,
        *,
        flow_type: str = "ticket_email",
        existing_retry_count: int = 0,
    ) -> bool:
        """Attempt one ticket email and persist any retry for a later cycle."""
        if not self.rate_limiter.quota_available():
            self.processing_logs.mark_rate_limited(
                finding_id=payload.finding_id,
                recipient_email=str(payload.recipient_email),
                email_subject=payload.subject,
                email_body=payload.body,
                email_html_body=payload.html_body,
                retry_count=existing_retry_count,
                next_attempt_at=self._next_retry_at(existing_retry_count + 1),
                error_message="SMTP rate limit exceeded",
                dedupe_key=payload.dedupe_key,
                priority=payload.priority,
                sla_target=payload.sla_target,
            )
            return False

        try:
            self.smtp_client.send(payload)
            self.rate_limiter.record_send(
                finding_id=payload.finding_id,
                recipient_email=str(payload.recipient_email),
                cc_emails=self._format_email_list(payload.cc_emails),
                flow_type=flow_type,
                delivery_mode=self.settings.manageengine_delivery_mode,
            )
            self.processing_logs.mark_sent(
                finding_id=payload.finding_id,
                recipient_email=str(payload.recipient_email),
                email_subject=payload.subject,
                email_body=payload.body,
                email_html_body=payload.html_body,
                retry_count=existing_retry_count,
                dedupe_key=payload.dedupe_key,
                priority=payload.priority,
                sla_target=payload.sla_target,
            )
            logger.info(
                "Email sent",
                extra={
                    "finding_id": payload.finding_id,
                    "dedupe_key": payload.dedupe_key,
                    "recipient_email": str(payload.recipient_email),
                    "to_emails": self._format_email_list(
                        self._payload_to_recipients(payload)
                    ),
                    "cc_emails": self._format_email_list(payload.cc_emails),
                    "flow_type": flow_type,
                    "status": ProcessingStatus.SENT.value,
                },
            )
            return True
        except Exception as error:
            retry_count = existing_retry_count + 1
            error_message = str(error)
            if (
                is_transient_smtp_error(error)
                and retry_count < self.settings.smtp_max_attempts
            ):
                self.processing_logs.mark_rate_limited(
                    finding_id=payload.finding_id,
                    recipient_email=str(payload.recipient_email),
                    email_subject=payload.subject,
                    email_body=payload.body,
                    email_html_body=payload.html_body,
                    retry_count=retry_count,
                    next_attempt_at=self._next_retry_at(retry_count),
                    error_message=error_message,
                    dedupe_key=payload.dedupe_key,
                    priority=payload.priority,
                    sla_target=payload.sla_target,
                )
                logger.warning(
                    "SMTP retry queued for a later scheduler cycle",
                    extra={
                        "finding_id": payload.finding_id,
                        "dedupe_key": payload.dedupe_key,
                        "recipient_email": str(payload.recipient_email),
                        "flow_type": flow_type,
                        "error_message": error_message,
                    },
                )
                return False

            self.processing_logs.mark_failed(
                finding_id=payload.finding_id,
                recipient_email=str(payload.recipient_email),
                email_subject=payload.subject,
                email_body=payload.body,
                email_html_body=payload.html_body,
                retry_count=retry_count,
                error_message=error_message,
                dedupe_key=payload.dedupe_key,
            )
            logger.warning(
                "SMTP delivery failed",
                extra={
                    "finding_id": payload.finding_id,
                    "dedupe_key": payload.dedupe_key,
                    "recipient_email": str(payload.recipient_email),
                    "flow_type": flow_type,
                    "status": ProcessingStatus.FAILED.value,
                    "error_message": error_message,
                },
            )
            return False

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
            logger.info(
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

    def process_notification_queue(self, finding_id: int | None = None) -> None:
        """Send due notification deliveries with database-backed retry leases."""
        for delivery in self.notification_deliveries.get_due(finding_id=finding_id):
            if not self.rate_limiter.quota_available():
                logger.info("Notification queue paused because SMTP quota is active")
                break
            if not self.notification_deliveries.acquire(
                delivery_id=delivery.id,
                worker_id=self.worker_id,
                lease_seconds=self.settings.notification_lease_ttl_seconds,
            ):
                continue
            self._deliver_notification(delivery)

    def _deliver_notification(self, delivery: NotificationDelivery) -> None:
        """Attempt one leased notification and persist its next state."""
        payload = EmailPayload(
            finding_id=delivery.finding_id,
            recipient_email=delivery.recipient_email,
            cc_emails=self._parse_stored_email_list(delivery.cc_emails),
            subject=delivery.email_subject,
            body=delivery.email_body,
            html_body=delivery.email_html_body,
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
                delivery_mode=self.settings.manageengine_delivery_mode,
            )
            self.notification_deliveries.mark_sent(delivery.id, self.worker_id)
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
            else:
                self.notification_deliveries.mark_failed(
                    delivery_id=delivery.id,
                    worker_id=self.worker_id,
                    retry_count=retry_count,
                    error_message=error_message,
                )
            logger.warning(
                "Notification delivery failed",
                extra={
                    "finding_id": delivery.finding_id,
                    "dedupe_key": delivery.dedupe_key,
                    "recipient_email": delivery.recipient_email,
                    "flow_type": "notify_email",
                    "error_message": error_message,
                },
            )

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
        return self.project_email_mapping.get(finding.product.lower())

    def _resolve_ticket_mailbox(
        self,
        finding: DefectDojoFinding,
        project_mapping: ProjectEmailMapping | None = None,
    ) -> str | None:
        """Resolve the ticket-creation mailbox for email-fetch mode."""
        ticket_email = self._validate_email(finding.ticket_email)
        if ticket_email:
            return ticket_email

        if not project_mapping:
            return None

        ticket_mailbox = self._validate_email(project_mapping.ticket_mailbox)
        if ticket_mailbox:
            return ticket_mailbox

        return None

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
                    merged[project.product_name.lower()] = project

        if self.settings.project_email_mapping_json:
            raw_mapping = json.loads(self.settings.project_email_mapping_json)
            json_mapping = ProjectEmailMappingConfig.model_validate(raw_mapping)
            for project in json_mapping.projects:
                merged[project.product_name.lower()] = project

        return merged
