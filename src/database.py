"""Create database connections and SQLAlchemy sessions."""

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from config import get_settings


class Base(DeclarativeBase):
    """Declarative base shared by all SQLAlchemy ORM models."""

    pass


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def get_engine() -> Engine:
    """Create once and return the configured SQLAlchemy engine."""
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_engine(settings.database_url, pool_pre_ping=True)
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    """Return the cached factory used to create database sessions."""
    global _session_factory
    if _session_factory is None:
        _session_factory = sessionmaker(
            bind=get_engine(), autoflush=False, autocommit=False
        )
    return _session_factory


def initialize_database() -> None:
    """Create any missing ORM tables before background jobs start."""
    import db_models  # noqa: F401

    Base.metadata.create_all(bind=get_engine())


def check_database_connection() -> bool:
    """Return whether the database accepts a simple validation query."""
    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
