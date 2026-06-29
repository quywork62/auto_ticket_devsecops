"""Remove dedupe claims table.

Revision ID: 20260629_0003
Revises: 20260625_0002
Create Date: 2026-06-29
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260629_0003"
down_revision: Union[str, None] = "20260625_0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Drop the optional dedupe lease table for single-worker deployments."""
    op.drop_table("dedupe_claims")


def downgrade() -> None:
    """Restore dedupe claims if rolling back to the previous design."""
    op.create_table(
        "dedupe_claims",
        sa.Column("dedupe_key", sa.String(length=80), primary_key=True),
        sa.Column("finding_id", sa.Integer(), nullable=False),
        sa.Column("lease_owner", sa.String(length=36)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_dedupe_claims_finding_id", "dedupe_claims", ["finding_id"])
    op.create_index(
        "ix_dedupe_claims_lease_expires_at",
        "dedupe_claims",
        ["lease_expires_at"],
    )
