"""Run the DefectDojo processing cycle on a configurable interval."""

import logging
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler

from config import Settings
from database import get_session_factory
from processor import FindingProcessor

logger = logging.getLogger(__name__)


class AppScheduler:
    """Own the background polling job and its application lifecycle."""

    def __init__(self, settings: Settings):
        """Create a UTC scheduler using the supplied application settings."""
        self.settings = settings
        self.scheduler = BackgroundScheduler(timezone="UTC")

    def start(self) -> None:
        """Register the polling job and run the first cycle immediately."""
        self.scheduler.add_job(
            self._run_cycle,
            "interval",
            seconds=self.settings.scheduler_interval_seconds,
            id="defectdojo_polling_job",
            max_instances=1,
            coalesce=True,
            misfire_grace_time=self.settings.scheduler_interval_seconds,
            replace_existing=True,
            next_run_time=datetime.now(timezone.utc),
        )
        self.scheduler.start()
        logger.info("Scheduler start")

    def shutdown(self) -> None:
        """Stop the scheduler without waiting for future jobs."""
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
            logger.info("Scheduler end")

    def is_running(self) -> bool:
        """Return whether APScheduler is currently active."""
        return self.scheduler.running

    def _run_cycle(self) -> None:
        """Run one processor cycle with an isolated database session."""
        db = get_session_factory()()
        try:
            processor = FindingProcessor(self.settings, db)
            processor.process_scheduler_cycle()
        finally:
            db.close()
