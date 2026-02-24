"""
OAuth 2.0 Authorization Code Model

Short-lived single-use codes issued during the Authorization Code flow.
Each code must be exchanged for tokens within its TTL (default 10 minutes).
"""
import uuid
import secrets
from datetime import datetime, timezone

from app.extensions import db


class OAuthAuthorizationCode(db.Model):
    __tablename__ = "oauth_authorization_codes"
    __table_args__ = (
        db.Index("ix_oauth_auth_codes_code", "code"),
    )

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    code = db.Column(
        db.String(255),
        unique=True,
        nullable=False,
        default=lambda: secrets.token_urlsafe(48),
    )

    # PKCE support (RFC 7636) — optional but recommended for public clients
    code_challenge = db.Column(db.String(128), nullable=True)
    code_challenge_method = db.Column(db.String(10), nullable=True)  # "S256" or "plain"

    # The redirect URI that was used when requesting the code
    redirect_uri = db.Column(db.String(512), nullable=False)

    # Granted scopes
    scope = db.Column(db.String(1000), nullable=False, default="")

    # State parameter (CSRF protection) — echoed back to client
    state = db.Column(db.String(255), nullable=True)

    # Nonce for OpenID Connect
    nonce = db.Column(db.String(255), nullable=True)

    # Expiry — codes are short-lived (10 min by default)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)

    # Usage tracking — codes are single-use
    is_used = db.Column(db.Boolean, default=False, nullable=False)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Relations
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    user = db.relationship("User")

    client_id = db.Column(db.String(36), db.ForeignKey("oauth_clients.id"), nullable=False)
    client = db.relationship("OAuthClient", back_populates="authorization_codes")

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return f"<OAuthAuthorizationCode id={self.id} user_id={self.user_id}>"

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at

    def mark_used(self) -> None:
        self.is_used = True
        self.used_at = datetime.now(timezone.utc)

    def is_valid(self) -> bool:
        """Return True only if the code can still be exchanged."""
        return not self.is_used and not self.is_expired
