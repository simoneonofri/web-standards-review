"""Expand artifact link object identifiers.

Revision ID: 0002_expand_link_object_id
Revises: 0001_initial
Create Date: 2026-06-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_expand_link_object_id"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("artifact_links") as batch_op:
        batch_op.alter_column(
            "object_id",
            existing_type=sa.String(length=36),
            type_=sa.String(length=512),
            existing_nullable=False,
        )


def downgrade() -> None:
    with op.batch_alter_table("artifact_links") as batch_op:
        batch_op.alter_column(
            "object_id",
            existing_type=sa.String(length=512),
            type_=sa.String(length=36),
            existing_nullable=False,
        )
