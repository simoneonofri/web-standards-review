"""Local vector index; ingestion tables and their contents remain unchanged."""
from alembic import op
from sqlalchemy import text

revision = "0004_local_vectors"
down_revision = "0003_tr_bootstrap_lite"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        bind.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    # Optional on SQLite lexical installations; the production Docker extra is required.
    try:
        from w3c_knowledge.search.vector_store import VectorBase
    except ImportError:
        if bind.dialect.name != "sqlite":
            raise
        return
    VectorBase.metadata.create_all(bind)


def downgrade():
    from w3c_knowledge.search.vector_store import VectorBase
    VectorBase.metadata.drop_all(op.get_bind())
