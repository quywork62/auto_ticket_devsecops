"""Define PostgreSQL audit models and processing statuses."""

import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp for ORM defaults."""
    return datetime.now(timezone.utc)


class ProcessingStatus(str, enum.Enum):
    """Supported states for processing one DefectDojo finding."""

    PENDING = "PENDING"
    SENT = "SENT"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    RATE_LIMITED = "RATE_LIMITED"
    INVALID_RECIPIENT = "INVALID_RECIPIENT"


class NotificationStatus(str, enum.Enum):
    """Delivery states for one independently addressed notification email."""

    PENDING = "PENDING"
    SENT = "SENT"
    RETRY_PENDING = "RETRY_PENDING"
    FAILED = "FAILED"


class ProcessingLog(Base):
    """Store the latest processing and ticket state for each finding."""

    __tablename__ = "processing_logs"
    __table_args__ = (UniqueConstraint("finding_id", name="uq_processing_logs_finding_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    dedupe_key: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    ticket_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    ticket_status: Mapped[str | None] = mapped_column(String(80), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    seen_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    priority: Mapped[str | None] = mapped_column(String(80), nullable=True)
    sla_target: Mapped[str | None] = mapped_column(String(80), nullable=True)
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    recipient_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    email_subject: Mapped[str | None] = mapped_column(String(500), nullable=True)
    email_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    email_html_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[ProcessingStatus] = mapped_column(
        Enum(ProcessingStatus, name="processing_status"),
        default=ProcessingStatus.PENDING,
        nullable=False,
        index=True,
    )
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    next_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )



class NotificationDelivery(Base):
    """Persist one notification recipient so delivery can be retried safely."""

    __tablename__ = "notification_deliveries"
    __table_args__ = (
        UniqueConstraint(
            "finding_id",
            "recipient_email",
            name="uq_notification_delivery_finding_recipient",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    dedupe_key: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    recipient_email: Mapped[str] = mapped_column(String(320), nullable=False)
    cc_emails: Mapped[str | None] = mapped_column(Text, nullable=True)
    email_subject: Mapped[str] = mapped_column(String(500), nullable=False)
    email_body: Mapped[str] = mapped_column(Text, nullable=False)
    email_html_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[NotificationStatus] = mapped_column(
        Enum(NotificationStatus, name="notification_status"),
        default=NotificationStatus.PENDING,
        nullable=False,
        index=True,
    )
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    next_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    lease_owner: Mapped[str | None] = mapped_column(String(36), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class SmtpSendEvent(Base):
    """Store one immutable audit row for every successful SMTP send."""

    __tablename__ = "smtp_send_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    recipient_email: Mapped[str] = mapped_column(String(320), nullable=False)
    cc_emails: Mapped[str | None] = mapped_column(Text, nullable=True)
    flow_type: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    delivery_mode: Mapped[str | None] = mapped_column(String(40), nullable=True)
    sent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )
