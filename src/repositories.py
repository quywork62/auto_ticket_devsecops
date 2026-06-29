"""Persist dedupe, delivery queue, processing, and SMTP audit state."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from db_models import (
    NotificationDelivery,
    NotificationStatus,
    ProcessingLog,
    ProcessingStatus,
    SmtpSendEvent,
    utc_now,
)
from schemas import EmailPayload


class ProcessingLogRepository:
    """Read and update the latest audit state for each finding."""

    def __init__(self, db: Session):
        """Bind repository operations to one SQLAlchemy session."""
        self.db = db

    def get_by_finding_id(self, finding_id: int) -> ProcessingLog | None:
        """Return the unique processing row for a finding ID."""
        return self.db.scalar(
            select(ProcessingLog).where(ProcessingLog.finding_id == finding_id)
        )

    def get_sent_or_queued_by_dedupe_key(self, dedupe_key: str) -> ProcessingLog | None:
        """Find the latest sent or queued logical duplicate."""
        return self.db.scalar(
            select(ProcessingLog)
            .where(ProcessingLog.dedupe_key == dedupe_key)
            .where(
                ProcessingLog.status.in_(
                    [ProcessingStatus.SENT, ProcessingStatus.RATE_LIMITED]
                )
            )
            .order_by(ProcessingLog.updated_at.desc())
            .limit(1)
        )

    def get_rate_limited_items(self, limit: int = 100) -> list[ProcessingLog]:
        """Return due queued ticket emails up to the requested batch size."""
        now = utc_now()
        return list(
            self.db.scalars(
                select(ProcessingLog)
                .where(ProcessingLog.status == ProcessingStatus.RATE_LIMITED)
                .where(
                    or_(
                        ProcessingLog.next_attempt_at.is_(None),
                        ProcessingLog.next_attempt_at <= now,
                    )
                )
                .order_by(ProcessingLog.updated_at.asc())
                .limit(limit)
            )
        )

    def mark_seen(
        self,
        *,
        finding_id: int,
        dedupe_key: str,
        priority: str | None,
        sla_target: str | None,
        sla_due_at: datetime | None,
    ) -> ProcessingLog:
        """Record that a finding was observed and refresh its metadata."""
        record = self.get_by_finding_id(finding_id)
        now = utc_now()
        if record is None:
            record = ProcessingLog(finding_id=finding_id)
            self.db.add(record)

        record.last_seen_at = now
        record.seen_count = (record.seen_count or 0) + 1
        record.dedupe_key = dedupe_key
        record.priority = priority
        record.sla_target = sla_target
        record.sla_due_at = sla_due_at
        record.updated_at = now
        self.db.commit()
        self.db.refresh(record)
        return record

    def upsert_status(
        self,
        *,
        finding_id: int,
        status: ProcessingStatus,
        recipient_email: str | None = None,
        email_subject: str | None = None,
        email_body: str | None = None,
        email_html_body: str | None = None,
        retry_count: int | None = None,
        next_attempt_at: datetime | None = None,
        error_message: str | None = None,
        processed_at: datetime | None = None,
        dedupe_key: str | None = None,
        priority: str | None = None,
        sla_target: str | None = None,
        sla_due_at: datetime | None = None,
    ) -> ProcessingLog:
        """Create or update one processing row with a supplied status."""
        record = self.get_by_finding_id(finding_id)
        now = utc_now()
        if record is None:
            record = ProcessingLog(finding_id=finding_id)
            self.db.add(record)

        record.status = status
        record.recipient_email = recipient_email
        record.email_subject = email_subject
        record.email_body = email_body
        record.email_html_body = email_html_body
        if retry_count is not None:
            record.retry_count = retry_count
        record.next_attempt_at = next_attempt_at
        record.error_message = error_message
        record.processed_at = processed_at
        if dedupe_key is not None:
            record.dedupe_key = dedupe_key
        if priority is not None:
            record.priority = priority
        if sla_target is not None:
            record.sla_target = sla_target
        if sla_due_at is not None:
            record.sla_due_at = sla_due_at
        record.last_seen_at = now
        record.updated_at = now
        self.db.commit()
        self.db.refresh(record)
        return record

    def mark_sent(
        self,
        *,
        finding_id: int,
        recipient_email: str,
        email_subject: str,
        email_body: str,
        email_html_body: str | None,
        retry_count: int,
        dedupe_key: str | None = None,
        priority: str | None = None,
        sla_target: str | None = None,
        sla_due_at: datetime | None = None,
    ) -> ProcessingLog:
        """Mark a finding as successfully delivered."""
        return self.upsert_status(
            finding_id=finding_id,
            status=ProcessingStatus.SENT,
            recipient_email=recipient_email,
            email_subject=email_subject,
            email_body=email_body,
            email_html_body=email_html_body,
            retry_count=retry_count,
            next_attempt_at=None,
            error_message=None,
            processed_at=utc_now(),
            dedupe_key=dedupe_key,
            priority=priority,
            sla_target=sla_target,
            sla_due_at=sla_due_at,
        )

    def mark_failed(
        self,
        *,
        finding_id: int,
        recipient_email: str | None,
        email_subject: str | None,
        email_body: str | None,
        email_html_body: str | None,
        retry_count: int,
        error_message: str,
        dedupe_key: str | None = None,
    ) -> ProcessingLog:
        """Mark ticket delivery as failed and retain the error for audit."""
        return self.upsert_status(
            finding_id=finding_id,
            status=ProcessingStatus.FAILED,
            recipient_email=recipient_email,
            email_subject=email_subject,
            email_body=email_body,
            email_html_body=email_html_body,
            retry_count=retry_count,
            next_attempt_at=None,
            error_message=error_message,
            processed_at=utc_now(),
            dedupe_key=dedupe_key,
        )

    def mark_rate_limited(
        self,
        *,
        finding_id: int,
        recipient_email: str,
        email_subject: str,
        email_body: str,
        email_html_body: str | None,
        retry_count: int = 0,
        next_attempt_at: datetime | None = None,
        error_message: str = "SMTP rate limit exceeded",
        dedupe_key: str | None = None,
        priority: str | None = None,
        sla_target: str | None = None,
        sla_due_at: datetime | None = None,
    ) -> ProcessingLog:
        """Queue a finding after SMTP quota exhaustion."""
        return self.upsert_status(
            finding_id=finding_id,
            status=ProcessingStatus.RATE_LIMITED,
            recipient_email=recipient_email,
            email_subject=email_subject,
            email_body=email_body,
            email_html_body=email_html_body,
            retry_count=retry_count,
            next_attempt_at=next_attempt_at,
            error_message=error_message,
            processed_at=None,
            dedupe_key=dedupe_key,
            priority=priority,
            sla_target=sla_target,
            sla_due_at=sla_due_at,
        )

    def mark_invalid_recipient(
        self,
        *,
        finding_id: int,
        error_message: str,
        dedupe_key: str | None = None,
        priority: str | None = None,
        sla_target: str | None = None,
        sla_due_at: datetime | None = None,
    ) -> ProcessingLog:
        """Record that no valid ticket mailbox could be resolved."""
        return self.upsert_status(
            finding_id=finding_id,
            status=ProcessingStatus.INVALID_RECIPIENT,
            error_message=error_message,
            processed_at=utc_now(),
            dedupe_key=dedupe_key,
            priority=priority,
            sla_target=sla_target,
            sla_due_at=sla_due_at,
        )

    def mark_skipped(
        self,
        *,
        finding_id: int,
        error_message: str,
        dedupe_key: str | None = None,
        priority: str | None = None,
        sla_target: str | None = None,
        sla_due_at: datetime | None = None,
    ) -> ProcessingLog:
        """Record a logical duplicate that must not create another ticket."""
        return self.upsert_status(
            finding_id=finding_id,
            status=ProcessingStatus.SKIPPED,
            error_message=error_message,
            processed_at=utc_now(),
            dedupe_key=dedupe_key,
            priority=priority,
            sla_target=sla_target,
            sla_due_at=sla_due_at,
        )

    def mark_ticket_created(
        self,
        *,
        finding_id: int,
        ticket_id: str | None,
        ticket_status: str | None,
        email_subject: str | None,
        email_body: str | None,
        email_html_body: str | None = None,
        dedupe_key: str | None = None,
        priority: str | None = None,
        sla_target: str | None = None,
        error_message: str | None = None,
        processing_status: ProcessingStatus = ProcessingStatus.SENT,
    ) -> ProcessingLog:
        """Store a ManageEngine API or dry-run result."""
        record = self.upsert_status(
            finding_id=finding_id,
            status=processing_status,
            email_subject=email_subject,
            email_body=email_body,
            email_html_body=email_html_body,
            retry_count=0,
            error_message=error_message,
            processed_at=utc_now(),
            dedupe_key=dedupe_key,
            priority=priority,
            sla_target=sla_target,
        )
        record.ticket_id = ticket_id
        record.ticket_status = ticket_status
        record.updated_at = utc_now()
        self.db.commit()
        self.db.refresh(record)
        return record



class NotificationDeliveryRepository:
    """Persist and lease independently addressed notification emails."""

    def __init__(self, db: Session):
        self.db = db

    def enqueue(self, payload: EmailPayload) -> NotificationDelivery:
        """Create an idempotent delivery row for one finding and recipient."""
        recipient = str(payload.recipient_email)
        existing = self.db.scalar(
            select(NotificationDelivery).where(
                NotificationDelivery.finding_id == payload.finding_id,
                NotificationDelivery.recipient_email == recipient,
            )
        )
        if existing is None:
            existing = NotificationDelivery(
                finding_id=payload.finding_id,
                dedupe_key=payload.dedupe_key or "",
                recipient_email=recipient,
                cc_emails=",".join(str(value) for value in payload.cc_emails) or None,
                email_subject=payload.subject,
                email_body=payload.body,
                email_html_body=payload.html_body,
                status=NotificationStatus.PENDING,
                next_attempt_at=utc_now(),
            )
            self.db.add(existing)
        elif existing.status != NotificationStatus.SENT:
            existing.cc_emails = (
                ",".join(str(value) for value in payload.cc_emails) or None
            )
            existing.email_subject = payload.subject
            existing.email_body = payload.body
            existing.email_html_body = payload.html_body
            existing.updated_at = utc_now()
        self.db.commit()
        self.db.refresh(existing)
        return existing

    def get_due(
        self, *, finding_id: int | None = None, limit: int = 100
    ) -> list[NotificationDelivery]:
        """Return due unsent notification rows whose ticket flow is complete."""
        now = utc_now()
        statement = (
            select(NotificationDelivery)
            .join(
                ProcessingLog,
                ProcessingLog.finding_id == NotificationDelivery.finding_id,
            )
            .where(ProcessingLog.status == ProcessingStatus.SENT)
            .where(
                NotificationDelivery.status.in_(
                    [NotificationStatus.PENDING, NotificationStatus.RETRY_PENDING]
                )
            )
            .where(
                or_(
                    NotificationDelivery.next_attempt_at.is_(None),
                    NotificationDelivery.next_attempt_at <= now,
                )
            )
            .order_by(NotificationDelivery.updated_at.asc())
            .limit(limit)
        )
        if finding_id is not None:
            statement = statement.where(NotificationDelivery.finding_id == finding_id)
        return list(self.db.scalars(statement))

    def acquire(
        self,
        *,
        delivery_id: int,
        worker_id: str,
        lease_seconds: int,
    ) -> bool:
        """Lease one due delivery so concurrent workers cannot send it twice."""
        now = utc_now()
        result = self.db.execute(
            update(NotificationDelivery)
            .where(NotificationDelivery.id == delivery_id)
            .where(NotificationDelivery.status != NotificationStatus.SENT)
            .where(
                or_(
                    NotificationDelivery.lease_owner.is_(None),
                    NotificationDelivery.lease_expires_at.is_(None),
                    NotificationDelivery.lease_expires_at <= now,
                )
            )
            .values(
                lease_owner=worker_id,
                lease_expires_at=now + timedelta(seconds=lease_seconds),
                updated_at=now,
            )
        )
        self.db.commit()
        return result.rowcount == 1

    def mark_sent(self, delivery_id: int, worker_id: str) -> None:
        """Mark a leased notification as delivered."""
        now = utc_now()
        self.db.execute(
            update(NotificationDelivery)
            .where(NotificationDelivery.id == delivery_id)
            .where(NotificationDelivery.lease_owner == worker_id)
            .values(
                status=NotificationStatus.SENT,
                sent_at=now,
                next_attempt_at=None,
                error_message=None,
                lease_owner=None,
                lease_expires_at=None,
                updated_at=now,
            )
        )
        self.db.commit()

    def mark_retry(
        self,
        *,
        delivery_id: int,
        worker_id: str,
        retry_count: int,
        next_attempt_at: datetime,
        error_message: str,
    ) -> None:
        """Release a failed notification back to the scheduler-backed retry queue."""
        self.db.execute(
            update(NotificationDelivery)
            .where(NotificationDelivery.id == delivery_id)
            .where(NotificationDelivery.lease_owner == worker_id)
            .values(
                status=NotificationStatus.RETRY_PENDING,
                retry_count=retry_count,
                next_attempt_at=next_attempt_at,
                error_message=error_message,
                lease_owner=None,
                lease_expires_at=None,
                updated_at=utc_now(),
            )
        )
        self.db.commit()

    def mark_failed(
        self,
        *,
        delivery_id: int,
        worker_id: str,
        retry_count: int,
        error_message: str,
    ) -> None:
        """Persist a terminal notification failure after retry exhaustion."""
        self.db.execute(
            update(NotificationDelivery)
            .where(NotificationDelivery.id == delivery_id)
            .where(NotificationDelivery.lease_owner == worker_id)
            .values(
                status=NotificationStatus.FAILED,
                retry_count=retry_count,
                next_attempt_at=None,
                error_message=error_message,
                lease_owner=None,
                lease_expires_at=None,
                updated_at=utc_now(),
            )
        )
        self.db.commit()


class SmtpRateLimitRepository:
    """Query and append successful SMTP events used for quota enforcement."""

    def __init__(self, db: Session):
        """Bind SMTP audit operations to one database session."""
        self.db = db

    def count_since(self, since: datetime) -> int:
        """Count successful SMTP events at or after a timestamp."""
        return int(
            self.db.scalar(
                select(func.count(SmtpSendEvent.id)).where(SmtpSendEvent.sent_at >= since)
            )
            or 0
        )

    def current_counts(self) -> tuple[int, int]:
        """Return send counts for the current minute and hour windows."""
        now = datetime.now(timezone.utc)
        minute_count = self.count_since(now - timedelta(minutes=1))
        hour_count = self.count_since(now - timedelta(hours=1))
        return minute_count, hour_count

    def record_send(
        self,
        *,
        finding_id: int,
        recipient_email: str,
        cc_emails: str | None = None,
        flow_type: str | None = None,
        delivery_mode: str | None = None,
    ) -> SmtpSendEvent:
        """Persist one successful SMTP delivery event."""
        event = SmtpSendEvent(
            finding_id=finding_id,
            recipient_email=recipient_email,
            cc_emails=cc_emails,
            flow_type=flow_type,
            delivery_mode=delivery_mode,
        )
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return event


class SmtpRateLimiter:
    """Apply per-minute and per-hour quotas using persisted SMTP events."""

    def __init__(
        self,
        repository: SmtpRateLimitRepository,
        max_per_minute: int,
        max_per_hour: int,
    ):
        """Configure repository-backed SMTP quota thresholds."""
        self.repository = repository
        self.max_per_minute = max_per_minute
        self.max_per_hour = max_per_hour

    def quota_available(self) -> bool:
        """Return whether both configured SMTP quotas allow another send."""
        minute_count, hour_count = self.repository.current_counts()
        return minute_count < self.max_per_minute and hour_count < self.max_per_hour

    def record_send(
        self,
        *,
        finding_id: int,
        recipient_email: str,
        cc_emails: str | None = None,
        flow_type: str | None = None,
        delivery_mode: str | None = None,
    ) -> None:
        """Delegate successful send auditing to the repository."""
        self.repository.record_send(
            finding_id=finding_id,
            recipient_email=recipient_email,
            cc_emails=cc_emails,
            flow_type=flow_type,
            delivery_mode=delivery_mode,
        )
