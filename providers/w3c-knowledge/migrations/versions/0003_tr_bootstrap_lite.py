"""Add W3C TR bootstrap lite tables.

Revision ID: 0003_tr_bootstrap_lite
Revises: 0002_expand_artifact_link_object_id
Create Date: 2026-06-23
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_tr_bootstrap_lite"
down_revision = "0002_expand_link_object_id"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    section_columns = {column["name"] for column in inspector.get_columns("specification_sections")}
    for name, column in {
        "parent_section_id": sa.Column("parent_section_id", sa.String(length=36), nullable=True),
        "heading_level": sa.Column("heading_level", sa.Integer(), nullable=True),
        "display_number": sa.Column("display_number", sa.String(length=128), nullable=True),
        "source_url": sa.Column("source_url", sa.Text(), nullable=True),
        "raw_html": sa.Column("raw_html", sa.Text(), nullable=True),
        "evidence_ids": sa.Column("evidence_ids", sa.JSON(), nullable=True),
    }.items():
        if name not in section_columns:
            op.add_column("specification_sections", column)

    existing_tables = set(inspector.get_table_names())
    if "specification_references" not in existing_tables:
        op.create_table(
            "specification_references",
        sa.Column("internal_id", sa.String(length=36), nullable=False),
        sa.Column("specification_version_id", sa.String(length=36), nullable=False),
        sa.Column("reference_type", sa.String(length=32), nullable=False),
        sa.Column("label", sa.String(length=256), nullable=False),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("section_fragment", sa.String(length=512), nullable=True),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("evidence_ids", sa.JSON(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["specification_version_id"], ["specification_versions.internal_id"]),
        sa.PrimaryKeyConstraint("internal_id"),
        sa.UniqueConstraint(
            "specification_version_id",
            "reference_type",
            "label",
            name="uq_spec_reference_version_type_label",
        ),
        )
        op.create_index("ix_spec_refs_version", "specification_references", ["specification_version_id"])
        op.create_index("ix_spec_refs_type", "specification_references", ["reference_type"])
        op.create_index("ix_spec_refs_label", "specification_references", ["label"])

    if "specification_idl_blocks" not in existing_tables:
        op.create_table(
            "specification_idl_blocks",
        sa.Column("internal_id", sa.String(length=36), nullable=False),
        sa.Column("specification_version_id", sa.String(length=36), nullable=False),
        sa.Column("section_id", sa.String(length=36), nullable=True),
        sa.Column("order", sa.Integer(), nullable=False),
        sa.Column("fragment", sa.String(length=512), nullable=True),
        sa.Column("idl_text", sa.Text(), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("content_hash", sa.String(length=128), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["section_id"], ["specification_sections.internal_id"]),
        sa.ForeignKeyConstraint(["specification_version_id"], ["specification_versions.internal_id"]),
        sa.PrimaryKeyConstraint("internal_id"),
        sa.UniqueConstraint("specification_version_id", "order", name="uq_spec_idl_version_order"),
        )
        op.create_index("ix_spec_idl_version", "specification_idl_blocks", ["specification_version_id"])
        op.create_index("ix_spec_idl_hash", "specification_idl_blocks", ["content_hash"])

    if "specification_consideration_statuses" not in existing_tables:
        op.create_table(
            "specification_consideration_statuses",
        sa.Column("internal_id", sa.String(length=36), nullable=False),
        sa.Column("specification_version_id", sa.String(length=36), nullable=False),
        sa.Column("consideration_type", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("section_id", sa.String(length=36), nullable=True),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("evidence_ids", sa.JSON(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["section_id"], ["specification_sections.internal_id"]),
        sa.ForeignKeyConstraint(["specification_version_id"], ["specification_versions.internal_id"]),
        sa.PrimaryKeyConstraint("internal_id"),
        sa.UniqueConstraint(
            "specification_version_id",
            "consideration_type",
            name="uq_spec_consideration_version_type",
        ),
        )
        op.create_index(
            "ix_spec_considerations_version",
            "specification_consideration_statuses",
            ["specification_version_id"],
        )
        op.create_index("ix_spec_considerations_type", "specification_consideration_statuses", ["consideration_type"])
        op.create_index("ix_spec_considerations_status", "specification_consideration_statuses", ["status"])


def downgrade() -> None:
    op.drop_index("ix_spec_considerations_status", table_name="specification_consideration_statuses")
    op.drop_index("ix_spec_considerations_type", table_name="specification_consideration_statuses")
    op.drop_index("ix_spec_considerations_version", table_name="specification_consideration_statuses")
    op.drop_table("specification_consideration_statuses")
    op.drop_index("ix_spec_idl_hash", table_name="specification_idl_blocks")
    op.drop_index("ix_spec_idl_version", table_name="specification_idl_blocks")
    op.drop_table("specification_idl_blocks")
    op.drop_index("ix_spec_refs_label", table_name="specification_references")
    op.drop_index("ix_spec_refs_type", table_name="specification_references")
    op.drop_index("ix_spec_refs_version", table_name="specification_references")
    op.drop_table("specification_references")
    op.drop_column("specification_sections", "evidence_ids")
    op.drop_column("specification_sections", "raw_html")
    op.drop_column("specification_sections", "source_url")
    op.drop_column("specification_sections", "display_number")
    op.drop_column("specification_sections", "heading_level")
    op.drop_column("specification_sections", "parent_section_id")
