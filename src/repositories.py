"""Persist processing state, delivery queue, and SMTP rate-limit state."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from db_models import (
    NotificationDelivery,
    NotificationStatus,
    ProcessingLog,
    ProcessingStatus,
    utc_now,
)
from schemas import EmailPayload


class ProcessingLogRepository:
    """Read and update one processing row per DefectDojo finding."""

    def __init__(self, db: Session):
        self.db = db

    def get_by_finding_id(self, finding_id: int) -> ProcessingLog | None:
        """Return the unique processing row for a finding ID."""
        return self.db.scalar(
            select(ProcessingLog).where(ProcessingLog.finding_id == finding_id)
        )

    def mark_seen(
        self,
        *,
        finding_id: int,
        priority: str | None = None,
        sla_target: str | None = None,
        sla_due_at: datetime | None = None,
    ) -> ProcessingLog:
        """Record that a finding was observed."""
        record = self.get_by_finding_id(finding_id)
        now = utc_now()
        if record is None:
            record = ProcessingLog(finding_id=finding_id)
            self.db.add(record)

        record.updated_at = now
        self.db.commit()
        self.db.refresh(record)
        return record

    def upsert_status(
        self,
        *,
        finding_id: int,
        status: ProcessingStatus,
        email_subject: str | None = None,
        retry_count: int | None = None,
        error_message: str | None = None,
        processed_at: datetime | None = None,
        **_: object,
    ) -> ProcessingLog:
        """Create or update one processing row with scoped audit columns."""
        record = self.get_by_finding_id(finding_id)
        now = utc_now()
        if record is None:
            record = ProcessingLog(finding_id=finding_id)
            self.db.add(record)

        record.status = status
        record.email_subject = email_subject
        if retry_count is not None:
            record.retry_count = retry_count
        record.error_message = error_message
        record.processed_at = processed_at
        record.updated_at = now
        self.db.commit()
        self.db.refresh(record)
        return record

    def mark_sent(
        self,
        *,
        finding_id: int,
        email_subject: str,
        retry_count: int,
        **kwargs: object,
    ) -> ProcessingLog:
        """Mark a finding as sent."""
        return self.upsert_status(
            finding_id=finding_id,
            status=ProcessingStatus.SENT,
            email_subject=email_subject,
            retry_count=retry_count,
            error_message=None,
            processed_at=utc_now(),
            **kwargs,
        )

    def mark_failed(
        self,
        *,
        finding_id: int,
        email_subject: str | None,
        retry_count: int,
        error_message: str,
        **kwargs: object,
    ) -> ProcessingLog:
        """Mark a finding as failed and retain the error for audit."""
        return self.upsert_status(
            finding_id=finding_id,
            status=ProcessingStatus.FAILED,
            email_subject=email_subject,
            retry_count=retry_count,
            error_message=error_message,
            processed_at=utc_now(),
            **kwargs,
        )

    def mark_rate_limited(
        self,
        *,
        finding_id: int,
        email_subject: str,
        retry_count: int = 0,
        error_message: str = "SMTP rate limit exceeded",
        **kwargs: object,
    ) -> ProcessingLog:
        """Mark a finding as waiting for queued SMTP delivery."""
        return self.upsert_status(
            finding_id=finding_id,
            status=ProcessingStatus.RATE_LIMITED,
            email_subject=email_subject,
            retry_count=retry_count,
            error_message=error_message,
            processed_at=None,
            **kwargs,
        )

    def mark_invalid_recipient(
        self,
        *,
        finding_id: int,
        error_message: str,
        **kwargs: object,
    ) -> ProcessingLog:
        """Record that no valid notification recipient could be resolved."""
        return self.upsert_status(
            finding_id=finding_id,
            status=ProcessingStatus.INVALID_RECIPIENT,
            error_message=error_message,
            processed_at=utc_now(),
            **kwargs,
        )

    def mark_skipped(
        self,
        *,
        finding_id: int,
        error_message: str,
        **kwargs: object,
    ) -> ProcessingLog:
        """Record a duplicate that must not send another email."""
        return self.upsert_status(
            finding_id=finding_id,
            status=ProcessingStatus.SKIPPED,
            error_message=error_message,
            processed_at=utc_now(),
            **kwargs,
        )

class NotificationDeliveryRepository:
    """Persist and retry one notification email per recipient."""

    def __init__(self, db: Session):
        self.db = db

    def sync_processing_status(self, finding_id: int) -> None:
        """Derive finding state from all recipients, never the last recipient."""
        rows = list(self.db.scalars(select(NotificationDelivery).where(
            NotificationDelivery.finding_id == finding_id
        )))
        if not rows:
            return
        states = {row.status for row in rows}
        if states & {NotificationStatus.PENDING, NotificationStatus.RETRY_PENDING}:
            status = ProcessingStatus.RATE_LIMITED
            message = "Waiting for notification deliveries"
        elif NotificationStatus.FAILED in states:
            status = ProcessingStatus.FAILED
            message = "One or more notification deliveries failed"
        else:
            status = ProcessingStatus.SENT
            message = None
        ProcessingLogRepository(self.db).upsert_status(
            finding_id=finding_id, status=status, email_subject=rows[0].email_subject,
            retry_count=max(row.retry_count for row in rows),
            error_message=message,
            processed_at=utc_now() if status != ProcessingStatus.RATE_LIMITED else None,
        )

    def enqueue(self, payload: EmailPayload) -> NotificationDelivery:
        """Create an idempotent delivery row for one finding and recipient."""
        recipient = str(payload.recipient_email)
        cc_emails = ",".join(str(value) for value in payload.cc_emails) or None
        existing = self.db.scalar(
            select(NotificationDelivery).where(
                NotificationDelivery.finding_id == payload.finding_id,
                NotificationDelivery.recipient_email == recipient,
            )
        )
        if existing is None:
            existing = NotificationDelivery(
                finding_id=payload.finding_id,
                recipient_email=recipient,
                cc_emails=cc_emails,
                email_subject=payload.subject,
                email_body=payload.body,
                status=NotificationStatus.PENDING,
                next_attempt_at=utc_now(),
            )
            self.db.add(existing)
        elif existing.status != NotificationStatus.SENT:
            existing.cc_emails = cc_emails
            existing.email_subject = payload.subject
            existing.email_body = payload.body
            existing.updated_at = utc_now()
        self.db.commit()
        self.db.refresh(existing)
        return existing

    def get_due(
        self, *, finding_id: int | None = None, limit: int = 100
    ) -> list[NotificationDelivery]:
        """Return due unsent notification rows."""
        now = utc_now()
        statement = (
            select(NotificationDelivery)
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

    def touch_due(
        self,
        *,
        delivery_id: int,
    ) -> bool:
        """Recheck eligibility in a single replica; this is not a lock or lease."""
        result = self.db.execute(
            update(NotificationDelivery)
            .where(NotificationDelivery.id == delivery_id)
            .where(NotificationDelivery.status.in_([
                NotificationStatus.PENDING, NotificationStatus.RETRY_PENDING
            ]))
            .where(or_(NotificationDelivery.next_attempt_at.is_(None),
                       NotificationDelivery.next_attempt_at <= utc_now()))
            .values(updated_at=utc_now())
        )
        self.db.commit()
        return result.rowcount == 1

    def mark_sent(self, delivery_id: int) -> None:
        """Mark a notification as delivered."""
        now = utc_now()
        self.db.execute(
            update(NotificationDelivery)
            .where(NotificationDelivery.id == delivery_id)
            .values(
                status=NotificationStatus.SENT,
                sent_at=now,
                next_attempt_at=None,
                updated_at=now,
            )
        )
        self.db.commit()

    def mark_retry(
        self,
        *,
        delivery_id: int,
        retry_count: int,
        next_attempt_at: datetime,
        error_message: str,
    ) -> None:
        """Release a failed notification back to the retry queue."""
        self.db.execute(
            update(NotificationDelivery)
            .where(NotificationDelivery.id == delivery_id)
            .values(
                status=NotificationStatus.RETRY_PENDING,
                retry_count=retry_count,
                next_attempt_at=next_attempt_at,
                updated_at=utc_now(),
            )
        )
        self.db.commit()

    def mark_failed(
        self,
        *,
        delivery_id: int,
        retry_count: int,
        error_message: str,
    ) -> None:
        """Persist a terminal notification failure after retry exhaustion."""
        self.db.execute(
            update(NotificationDelivery)
            .where(NotificationDelivery.id == delivery_id)
            .values(
                status=NotificationStatus.FAILED,
                retry_count=retry_count,
                next_attempt_at=None,
                updated_at=utc_now(),
            )
        )
        self.db.commit()


class SmtpRateLimitRepository:
    """Query successful notification deliveries used for SMTP quota enforcement."""

    def __init__(self, db: Session):
        self.db = db

    def count_since(self, since: datetime) -> int:
        """Count successful notification emails at or after a timestamp."""
        return int(
            self.db.scalar(
                select(func.count(NotificationDelivery.id)).where(
                    NotificationDelivery.status == NotificationStatus.SENT,
                    NotificationDelivery.sent_at >= since,
                )
            )
            or 0
        )

    def current_counts(self) -> tuple[int, int]:
        """Return send counts for current minute and hour windows."""
        now = datetime.now(timezone.utc)
        minute_count = self.count_since(now - timedelta(minutes=1))
        hour_count = self.count_since(now - timedelta(hours=1))
        return minute_count, hour_count


class SmtpRateLimiter:
    """Apply per-minute and per-hour quotas using notification deliveries."""

    def __init__(
        self,
        repository: SmtpRateLimitRepository,
        max_per_minute: int,
        max_per_hour: int,
    ):
        self.repository = repository
        self.max_per_minute = max_per_minute
        self.max_per_hour = max_per_hour

    def quota_available(self) -> bool:
        """Return whether both configured SMTP quotas allow another send."""
        minute_count, hour_count = self.repository.current_counts()
        return minute_count < self.max_per_minute and hour_count < self.max_per_hour
