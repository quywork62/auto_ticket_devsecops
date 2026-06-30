"""Expose lightweight application and database health endpoints."""

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request, Response, status
from pydantic import ValidationError

from config import get_settings
from database import check_database_connection
from schemas import ProjectEmailMappingConfig

router = APIRouter()


@router.get("/health")
def health_check(request: Request, response: Response) -> dict[str, Any]:
    """Report application, database, and scheduler health."""
    dependencies = _dependency_status(request)
    database_connected = dependencies["database"] == "connected"
    scheduler_running = dependencies["scheduler"] == "running"
    healthy = database_connected and scheduler_running
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ok" if healthy else "error",
        **dependencies,
    }


@router.get("/health/db")
def db_health_check(response: Response) -> dict[str, str]:
    """Report database connectivity only."""
    database_connected = check_database_connection()
    if not database_connected:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {"status": "ok" if database_connected else "error"}


@router.get("/health/dependencies")
def dependency_health_check(request: Request, response: Response) -> dict[str, Any]:
    """Report dependency readiness without calling external APIs."""
    dependencies = _dependency_status(request)
    healthy = all(
        value in {"connected", "running", "configured"}
        for value in dependencies.values()
    )
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ok" if healthy else "error",
        **dependencies,
    }


def _dependency_status(request: Request) -> dict[str, str]:
    """Return safe health details for local and configured dependencies."""
    settings = get_settings()
    scheduler = getattr(request.app.state, "scheduler", None)
    return {
        "database": "connected" if check_database_connection() else "disconnected",
        "scheduler": (
            "running"
            if scheduler is not None and scheduler.is_running()
            else "stopped"
        ),
        "defectdojo": (
            "configured"
            if settings.defectdojo_base_url and settings.defectdojo_api_token
            else "missing_config"
        ),
        "smtp": (
            "configured"
            if settings.smtp_host and settings.smtp_from_email
            else "missing_config"
        ),
        "project_mapping": _project_mapping_status(),
    }


def _project_mapping_status() -> str:
    """Return whether the configured project mapping is present and valid."""
    settings = get_settings()
    try:
        if settings.project_email_mapping_json:
            ProjectEmailMappingConfig.model_validate_json(
                settings.project_email_mapping_json
            )
            return "configured"

        if settings.project_email_mapping_file:
            path = Path(settings.project_email_mapping_file)
            if not path.exists():
                return "missing_config"
            ProjectEmailMappingConfig.model_validate_json(
                path.read_text(encoding="utf-8")
            )
            return "configured"
    except (OSError, ValueError, ValidationError):
        return "invalid_config"

    return "missing_config"
