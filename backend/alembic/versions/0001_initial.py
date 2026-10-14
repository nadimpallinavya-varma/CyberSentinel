from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("assets", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("name", sa.String(120), nullable=False), sa.Column("kind", sa.String(40), nullable=False), sa.Column("environment", sa.String(40), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False)); op.create_index("ix_assets_name", "assets", ["name"], unique=True)
    op.create_table("security_events", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("event_type", sa.String(60), nullable=False), sa.Column("username", sa.String(160), nullable=False), sa.Column("source_ip", sa.String(64), nullable=False), sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=False), sa.Column("success", sa.Boolean(), nullable=False), sa.Column("is_demo", sa.Boolean(), nullable=False), sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False), sa.Column("metadata", sa.JSON(), nullable=False));
    for name, cols in [("event_type", ["event_type"]), ("username", ["username"]), ("source_ip", ["source_ip"]), ("asset_id", ["asset_id"]), ("occurred_at", ["occurred_at"])]: op.create_index("ix_security_events_"+name, "security_events", cols)
    op.create_table("incidents", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("title", sa.String(200), nullable=False), sa.Column("severity", sa.String(20), nullable=False), sa.Column("status", sa.String(24), nullable=False), sa.Column("source_ip", sa.String(64), nullable=False), sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=False), sa.Column("detection_rule", sa.String(80), nullable=False), sa.Column("evidence", sa.JSON(), nullable=False), sa.Column("analyst_notes", sa.Text(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False)); op.create_index("ix_incidents_severity", "incidents", ["severity"]); op.create_index("ix_incidents_status", "incidents", ["status"])

def downgrade():
    op.drop_table("incidents"); op.drop_table("security_events"); op.drop_table("assets")
