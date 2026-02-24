"""Initial schema — users, oauth_clients, oauth_tokens, oauth_authorization_codes

Revision ID: 0001
Revises:
Create Date: 2024-01-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ------------------------------------------------------------------
    # users
    # ------------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("username", sa.String(80), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("first_name", sa.String(100), nullable=True),
        sa.Column("last_name", sa.String(100), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("is_superuser", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_ip", sa.String(45), nullable=True),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("email_verification_token", sa.String(255), nullable=True),
        sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("password_reset_token", sa.String(255), nullable=True),
        sa.Column("password_reset_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("email", name="uq_users_email"),
        sa.UniqueConstraint("username", name="uq_users_username"),
    )
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_username", "users", ["username"])

    # ------------------------------------------------------------------
    # oauth_clients
    # ------------------------------------------------------------------
    op.create_table(
        "oauth_clients",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("client_id", sa.String(48), nullable=False),
        sa.Column("client_secret_hash", sa.String(255), nullable=True),
        sa.Column("client_name", sa.String(200), nullable=False),
        sa.Column("client_description", sa.Text(), nullable=True),
        sa.Column("client_uri", sa.String(512), nullable=True),
        sa.Column("logo_uri", sa.String(512), nullable=True),
        sa.Column("redirect_uris", sa.Text(), nullable=False),
        sa.Column("grant_types", sa.String(500), nullable=False),
        sa.Column("response_types", sa.String(500), nullable=False),
        sa.Column("scope", sa.String(1000), nullable=False),
        sa.Column("client_type", sa.String(20), nullable=False),
        sa.Column("owner_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("client_id", name="uq_oauth_clients_client_id"),
    )
    op.create_index("ix_oauth_clients_client_id", "oauth_clients", ["client_id"])

    # ------------------------------------------------------------------
    # oauth_tokens
    # ------------------------------------------------------------------
    op.create_table(
        "oauth_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("access_token", sa.String(512), nullable=False),
        sa.Column("refresh_token", sa.String(512), nullable=True),
        sa.Column("token_type", sa.String(40), nullable=False, server_default="Bearer"),
        sa.Column("scope", sa.String(1000), nullable=False, server_default=""),
        sa.Column("access_token_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("refresh_token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("client_id", sa.String(36), sa.ForeignKey("oauth_clients.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("access_token", name="uq_oauth_tokens_access_token"),
        sa.UniqueConstraint("refresh_token", name="uq_oauth_tokens_refresh_token"),
    )
    op.create_index("ix_oauth_tokens_access_token", "oauth_tokens", ["access_token"])
    op.create_index("ix_oauth_tokens_refresh_token", "oauth_tokens", ["refresh_token"])

    # ------------------------------------------------------------------
    # oauth_authorization_codes
    # ------------------------------------------------------------------
    op.create_table(
        "oauth_authorization_codes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("code", sa.String(255), nullable=False),
        sa.Column("code_challenge", sa.String(128), nullable=True),
        sa.Column("code_challenge_method", sa.String(10), nullable=True),
        sa.Column("redirect_uri", sa.String(512), nullable=False),
        sa.Column("scope", sa.String(1000), nullable=False, server_default=""),
        sa.Column("state", sa.String(255), nullable=True),
        sa.Column("nonce", sa.String(255), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_used", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("client_id", sa.String(36), sa.ForeignKey("oauth_clients.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("code", name="uq_oauth_auth_codes_code"),
    )
    op.create_index("ix_oauth_auth_codes_code", "oauth_authorization_codes", ["code"])


def downgrade():
    op.drop_table("oauth_authorization_codes")
    op.drop_table("oauth_tokens")
    op.drop_table("oauth_clients")
    op.drop_table("users")
