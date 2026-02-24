"""
User Repository — Data Access Layer

All database reads/writes for the User model go through this class.
Services call this repository and never touch SQLAlchemy directly.
"""
from __future__ import annotations

import logging
from typing import Optional

from app.extensions import db
from app.models.user import User

logger = logging.getLogger(__name__)


class UserRepository:
    """Static repository for User persistence operations."""

    @staticmethod
    def get_by_id(user_id: str) -> Optional[User]:
        return db.session.get(User, user_id)

    @staticmethod
    def get_by_email(email: str) -> Optional[User]:
        return User.query.filter_by(email=email.lower().strip()).first()

    @staticmethod
    def get_by_username(username: str) -> Optional[User]:
        return User.query.filter_by(username=username.strip()).first()

    @staticmethod
    def get_by_email_or_username(identifier: str) -> Optional[User]:
        """Find a user by either email or username (used during login)."""
        identifier = identifier.strip()
        return (
            User.query.filter(
                (User.email == identifier.lower()) | (User.username == identifier)
            ).first()
        )

    @staticmethod
    def get_by_verification_token(token: str) -> Optional[User]:
        return User.query.filter_by(email_verification_token=token).first()

    @staticmethod
    def get_by_reset_token(token: str) -> Optional[User]:
        return User.query.filter_by(password_reset_token=token).first()

    @staticmethod
    def create(
        email: str,
        username: str,
        password_hash: str,
        first_name: str = None,
        last_name: str = None,
    ) -> User:
        user = User(
            email=email.lower().strip(),
            username=username.strip(),
            password_hash=password_hash,
            first_name=first_name,
            last_name=last_name,
        )
        db.session.add(user)
        db.session.commit()
        logger.info("Created user id=%s email=%s", user.id, user.email)
        return user

    @staticmethod
    def save(user: User) -> User:
        db.session.add(user)
        db.session.commit()
        return user

    @staticmethod
    def delete(user: User) -> None:
        db.session.delete(user)
        db.session.commit()
        logger.info("Deleted user id=%s", user.id)

    @staticmethod
    def list_all(page: int = 1, per_page: int = 20) -> tuple[list[User], int]:
        """Return a paginated list of users and the total count."""
        pagination = User.query.order_by(User.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        return pagination.items, pagination.total

    @staticmethod
    def email_exists(email: str) -> bool:
        return (
            db.session.query(
                User.query.filter_by(email=email.lower().strip()).exists()
            ).scalar()
        )

    @staticmethod
    def username_exists(username: str) -> bool:
        return (
            db.session.query(
                User.query.filter_by(username=username.strip()).exists()
            ).scalar()
        )
