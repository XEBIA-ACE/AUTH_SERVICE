"""
User Model

Represents an authenticated identity in the system.
Passwords are stored as bcrypt hashes — plaintext is never persisted.
"""
import uuid
from datetime import datetime, timezone

from app.extensions import db


class User(db.Model):
    __tablename__ = "users"
    __table_args__ = (
        db.Index("ix_users_email", "email"),
        db.Index("ix_users_username", "username"),
    )

    id = db.Column(
        db.String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    # Profile
    first_name = db.Column(db.String(100), nullable=True)
    last_name = db.Column(db.String(100), nullable=True)

    # Account state
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    is_superuser = db.Column(db.Boolean, default=False, nullable=False)

    # Security tracking
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)  # IPv6 max length
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)

    # Email verification
    email_verification_token = db.Column(db.String(255), nullable=True)
    email_verified_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Password reset
    password_reset_token = db.Column(db.String(255), nullable=True)
    password_reset_expires_at = db.Column(db.DateTime(timezone=True), nullable=True)

    # Timestamps
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
        "OAuthToken", back_populates="user", cascade="all, delete-orphan"
    )
    oauth_clients = db.relationship(
        "OAuthClient", back_populates="owner", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email}>"

    @property
    def full_name(self) -> str:
        parts = filter(None, [self.first_name, self.last_name])
        return " ".join(parts) or self.username

    def is_locked(self) -> bool:
        """Return True if the account is temporarily locked due to failed logins."""
        if self.locked_until is None:
            return False
        return datetime.now(timezone.utc) < self.locked_until

    def to_dict(self, include_sensitive: bool = False) -> dict:
        """Serialize user to a safe dictionary representation."""
        data = {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "full_name": self.full_name,
            "is_active": self.is_active,
            "is_verified": self.is_verified,
            "is_superuser": self.is_superuser,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
        if include_sensitive:
            data.update(
                {
                    "failed_login_attempts": self.failed_login_attempts,
                    "locked_until": self.locked_until.isoformat() if self.locked_until else None,
                    "last_login_ip": self.last_login_ip,
                }
            )
        return data
