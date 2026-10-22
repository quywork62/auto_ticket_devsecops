"""Single source of truth for severity-based remediation KPI targets."""

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from schemas import SlaPolicy

SLA_TIMEZONE = ZoneInfo("Asia/Ho_Chi_Minh")
SLA_BY_SEVERITY = {
    "critical": ("P1/Critical", timedelta(hours=4), "4 hours"),
    "high": ("P2/High", timedelta(hours=24), "24 hours"),
    "medium": ("P3/Medium", timedelta(days=7), "7 days"),
    "low": ("P4/Low", timedelta(days=30), "30 days"),
    "informational": ("P5/Info", None, "Best effort"),
}


def policy_for_severity(severity: str, *, started_at: datetime | None = None) -> SlaPolicy:
    """Calculate from an explicit aware timestamp or current processing time."""
    normalized = severity.strip().lower()
    if normalized == "info":
        normalized = "informational"
    priority, duration, target = SLA_BY_SEVERITY.get(
        normalized, SLA_BY_SEVERITY["informational"]
    )
    start = started_at if started_at is not None else datetime.now(SLA_TIMEZONE)
    if start.tzinfo is None or start.utcoffset() is None:
        raise ValueError("SLA start must include a timezone")
    start = start.astimezone(SLA_TIMEZONE)
    return SlaPolicy(severity=severity, priority=priority, target=target,
                     due_at=start + duration if duration is not None else None)


def format_due_at(due_at: datetime | None) -> str | None:
    """Render hour and day deadlines consistently in Vietnam local time."""
    if due_at is None:
        return None
    if due_at.tzinfo is None or due_at.utcoffset() is None:
        raise ValueError("SLA deadline must include a timezone")
    return due_at.astimezone(SLA_TIMEZONE).strftime("%Y-%m-%d %H:%M")
