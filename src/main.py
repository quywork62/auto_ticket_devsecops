"""FastAPI entrypoint, logging setup, and application lifecycle management."""

from contextlib import asynccontextmanager
import logging
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

from fastapi import FastAPI

from config import get_settings
from health import router as health_router
from scheduler import AppScheduler

LOG_TIMEZONE = ZoneInfo("Asia/Ho_Chi_Minh")


class ContextFormatter(logging.Formatter):
    """Append known DevSecOps context fields to each structured log line."""

    def formatTime(
        self,
        record: logging.LogRecord,
        datefmt: str | None = None,
    ) -> str:
        """Render log timestamps in Vietnam local time."""
        created_at = datetime.fromtimestamp(record.created, LOG_TIMEZONE)
        if datefmt:
            return created_at.strftime(datefmt)
        return created_at.isoformat()

    def format(self, record: logging.LogRecord) -> str:
        """Format the base log message and append available context values."""
        fields = {
            "finding_id": getattr(record, "finding_id", None)
            or getattr(record, "dedupe_key", None),
            "delivery_id": getattr(record, "delivery_id", None),
            "product": getattr(record, "product", None),
            "severity": getattr(record, "severity", None),
            "recipient_email": getattr(record, "recipient_email", None),
            "total_finding": getattr(record, "total_finding", None),
            "new_finding": getattr(record, "new_finding", None),
            "project_count": getattr(record, "project_count", None),
            "flow_type": getattr(record, "flow_type", None),
            "missing_fields": getattr(record, "missing_fields", None),
            "status": getattr(record, "status", None),
            "error_message": getattr(record, "error_message", None),
        }
        context = " ".join(
            f"{key}={value}" for key, value in fields.items() if value is not None
        )
        message = super().format(record)
        return f"{message} {context}" if context else message


def configure_logging() -> None:
    """Configure process-wide logging to write structured lines to stdout."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        ContextFormatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    logging.getLogger("apscheduler").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start the scheduler after deployment migrations have completed."""
    configure_logging()
    settings = get_settings()
    scheduler = AppScheduler(settings)
    app.state.scheduler = scheduler
    scheduler.start()
    try:
        yield
    finally:
        scheduler.shutdown()


app = FastAPI(
    title="DevSecOps Auto Ticket Notification Service",
    version="0.1.0",
    lifespan=lifespan,
)
app.include_router(health_router)
