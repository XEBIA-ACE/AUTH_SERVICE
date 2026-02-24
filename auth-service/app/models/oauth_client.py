"""
OAuth 2.0 Client Model

Represents a registered third-party application that can request
access to user resources via the OAuth 2.0 authorization flows.
"""
import uuid
import secrets
from datetime import datetime, timezone

from app.extensions import db


class OAuthClient(db.Model):
    __tablename__ = "oauth_clients"
    __table_args__ = (
        db.Index("ix_oauth_clients_client_id", "client_id"),
    )

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    # OAuth client credentials
    client_id = db.Column(
        db.String(48),
        unique=True,
        nullable=False,
        default=lambda: secrets.token_urlsafe(32),
    )
    client_secret_hash = db.Column(db.String(255), nullable=True)  # Null for public clients

    # Registration metadata
    client_name = db.Column(db.String(200), nullable=False)
    client_description = db.Column(db.Text, nullable=True)
    client_uri = db.Column(db.String(512), nullable=True)
    logo_uri = db.Column(db.String(512), nullable=True)

    # Allowed redirect URIs (stored as newline-separated list)
    redirect_uris = db.Column(db.Text, nullable=False)

    # OAuth 2.0 grant types allowed for this client (space-separated)
    # e.g. "authorization_code refresh_token client_credentials"
    grant_types = db.Column(db.String(500), nullable=False, default="authorization_code")

    # OAuth 2.0 response types (space-separated)
    # e.g. "code token"
    response_types = db.Column(db.String(500), nullable=False, default="code")

    # Allowed scopes (space-separated)
    # e.g. "read write profile email"
    scope = db.Column(db.String(1000), nullable=False, default="read")

    # Client type: 'confidential' (server-side) or 'public' (SPA/mobile)
    client_type = db.Column(db.String(20), nullable=False, default="confidential")

    # Owner (registered developer / service account)
    owner_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    owner = db.relationship("User", back_populates="oauth_clients")

    is_active = db.Column(db.Boolean, default=True, nullable=False)

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    oauth_tokens = db.relationship(
        "OAuthToken", back_populates="client", cascade="all, delete-orphan"
    )
    authorization_codes = db.relationship(
        "OAuthAuthorizationCode", back_populates="client", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<OAuthClient id={self.id} name={self.client_name}>"

    def get_redirect_uris(self) -> list[str]:
        """Return the list of allowed redirect URIs."""
        return [uri.strip() for uri in self.redirect_uris.splitlines() if uri.strip()]

    def get_grant_types(self) -> list[str]:
        return self.grant_types.split()

    def get_response_types(self) -> list[str]:
        return self.response_types.split()

    def get_allowed_scopes(self) -> list[str]:
        return self.scope.split()

    def is_redirect_uri_allowed(self, redirect_uri: str) -> bool:
        return redirect_uri in self.get_redirect_uris()

    def is_grant_type_allowed(self, grant_type: str) -> bool:
        return grant_type in self.get_grant_types()

    def is_scope_allowed(self, requested_scope: str) -> bool:
        allowed = set(self.get_allowed_scopes())
        requested = set(requested_scope.split())
        return requested.issubset(allowed)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "client_id": self.client_id,
            "client_name": self.client_name,
            "client_description": self.client_description,
            "client_uri": self.client_uri,
            "redirect_uris": self.get_redirect_uris(),
            "grant_types": self.get_grant_types(),
            "response_types": self.get_response_types(),
            "scope": self.scope,
            "client_type": self.client_type,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
        }
