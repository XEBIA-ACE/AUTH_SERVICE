"""
OAuth 2.0 Token Model

Stores issued access and refresh tokens for OAuth flows.
"""
import uuid
import secrets
from datetime import datetime, timezone, timedelta

from app.extensions import db


class OAuthToken(db.Model):
    __tablename__ = "oauth_tokens"
    __table_args__ = (
        db.Index("ix_oauth_tokens_access_token", "access_token"),
        db.Index("ix_oauth_tokens_refresh_token", "refresh_token"),
    )

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # Token values — stored as opaque bearer strings
    access_token = db.Column(db.String(512), unique=True, nullable=False)
    refresh_token = db.Column(db.String(512), unique=True, nullable=True)

    # Token type per RFC 6750 (always "Bearer" for this implementation)
    token_type = db.Column(db.String(40), nullable=False, default="Bearer")

    # Granted scopes (space-separated)
    scope = db.Column(db.String(1000), nullable=False, default="")

    # Expiry
    access_token_expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    refresh_token_expires_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Revocation
    is_revoked = db.Column(db.Boolean, default=False, nullable=False)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Relations
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    user = db.relationship("User", back_populates="oauth_tokens")

    client_id = db.Column(db.String(36), db.ForeignKey("oauth_clients.id"), nullable=False)
    client = db.relationship("OAuthClient", back_populates="oauth_tokens")

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return f"<OAuthToken id={self.id} user_id={self.user_id}>"

    @property
    def is_access_token_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.access_token_expires_at

    @property
    def is_refresh_token_expired(self) -> bool:
        if self.refresh_token_expires_at is None:
            return True
        return datetime.now(timezone.utc) >= self.refresh_token_expires_at

    def revoke(self) -> None:
        self.is_revoked = True
        self.revoked_at = datetime.now(timezone.utc)

    def get_scopes(self) -> list[str]:
        return self.scope.split() if self.scope else []

    def to_dict(self) -> dict:
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": max(
                0,
                int(
                    (self.access_token_expires_at - datetime.now(timezone.utc)).total_seconds()
                ),
            ),
            "refresh_token": self.refresh_token,
            "scope": self.scope,
        }
