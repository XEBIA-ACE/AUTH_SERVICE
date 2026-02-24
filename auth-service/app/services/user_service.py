"""
User Service — User profile management business logic.
"""
from __future__ import annotations

import logging
from typing import Optional

from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.services.auth_service import AuthError
from app.utils.security import verify_password, hash_password
from app.utils.validators import validate_email, validate_username, ValidationError

logger = logging.getLogger(__name__)


class UserService:
    """Profile and account management operations."""

    @staticmethod
    def get_user(user_id: str) -> User:
        user = UserRepository.get_by_id(user_id)
        if not user:
            raise AuthError("User not found", status_code=404)
        return user

    @staticmethod
    def list_users(page: int = 1, per_page: int = 20) -> tuple[list[User], int]:
        return UserRepository.list_all(page=page, per_page=per_page)

    @staticmethod
    def update_profile(
        user_id: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        username: Optional[str] = None,
    ) -> User:
        """
        Update mutable profile fields.

        Args:
            user_id: The ID of the user to update.
            first_name: New first name (None = no change).
            last_name: New last name (None = no change).
            username: New username (None = no change).

        Returns:
            The updated User.
        """
        user = UserRepository.get_by_id(user_id)
        if not user:
            raise AuthError("User not found", status_code=404)

        if username is not None:
            username = validate_username(username)
            existing = UserRepository.get_by_username(username)
            if existing and existing.id != user_id:
                raise AuthError("Username is already taken", status_code=409)
            user.username = username

        if first_name is not None:
            user.first_name = first_name.strip() or None
        if last_name is not None:
            user.last_name = last_name.strip() or None

        UserRepository.save(user)
        logger.info("Updated profile for user_id=%s", user_id)
        return user

    @staticmethod
    def change_password(
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> User:
        """
        Change a user's password after verifying the current one.

        Args:
            user_id: The authenticated user's ID.
            current_password: The user's existing plaintext password.
            new_password: The desired new plaintext password.

        Returns:
            The updated User.
        """
        from flask import current_app
        from app.utils.validators import validate_password

        user = UserRepository.get_by_id(user_id)
        if not user:
            raise AuthError("User not found", status_code=404)

        if not verify_password(current_password, user.password_hash):
            raise AuthError("Current password is incorrect", status_code=400)

        validate_password(
            new_password,
            min_length=current_app.config["PASSWORD_MIN_LENGTH"],
            max_length=current_app.config["PASSWORD_MAX_LENGTH"],
        )

        user.password_hash = hash_password(new_password)
        UserRepository.save(user)
        logger.info("Password changed for user_id=%s", user_id)
        return user

    @staticmethod
    def deactivate(user_id: str, requesting_user_id: str, is_superuser: bool) -> User:
        """
        Deactivate a user account.

        Only the account owner or a superuser may deactivate an account.
        """
        if user_id != requesting_user_id and not is_superuser:
            raise AuthError("Insufficient permissions", status_code=403)

        user = UserRepository.get_by_id(user_id)
        if not user:
            raise AuthError("User not found", status_code=404)

        user.is_active = False
        UserRepository.save(user)
        logger.info(
            "User deactivated: user_id=%s by=%s", user_id, requesting_user_id
        )
        return user
