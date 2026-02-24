"""
Auth Service — Core authentication business logic.

Handles registration, login, logout, email verification, and password reset.
This layer enforces all domain rules; the repository layer handles I/O.
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from flask import current_app, request

from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.services.token_service import TokenService
from app.utils.security import hash_password, verify_password
from app.utils.validators import (
    ValidationError,
    validate_email,
    validate_username,
    validate_password,
)

logger = logging.getLogger(__name__)

# Account lockout policy
_MAX_FAILED_ATTEMPTS = 5
_LOCKOUT_DURATION_MINUTES = 15


class AuthError(Exception):
    """Raised when an authentication or authorization check fails."""

    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class AuthService:
    """Stateless service that orchestrates authentication flows."""

    @staticmethod
    def register(
        email: str,
        username: str,
        password: str,
        first_name: str = None,
        last_name: str = None,
    ) -> User:
        """
        Register a new user account.

        Raises:
            ValidationError: If input is invalid.
            AuthError: If email or username already exists.
        """
        email = validate_email(email)
        username = validate_username(username)
        validate_password(
            password,
            min_length=current_app.config["PASSWORD_MIN_LENGTH"],
            max_length=current_app.config["PASSWORD_MAX_LENGTH"],
        )

        if UserRepository.get_by_email(email):
            raise AuthError("Email address is already registered", status_code=409)
        if UserRepository.get_by_username(username):
            raise AuthError("Username is already taken", status_code=409)

        password_hash = hash_password(password)
        verification_token = secrets.token_urlsafe(32)

        user = UserRepository.create(
            email=email,
            username=username,
            password_hash=password_hash,
            first_name=first_name,
            last_name=last_name,
        )
        # Store verification token (in a real app, email it to the user)
        user.email_verification_token = verification_token
        UserRepository.save(user)

        logger.info("Registered new user id=%s email=%s", user.id, user.email)
        return user

    @staticmethod
    def login(identifier: str, password: str) -> tuple[User, dict]:
        """
        Authenticate a user by email/username + password.

        Args:
            identifier: Email address or username.
            password: Plaintext password.

        Returns:
            Tuple of (User, token_pair_dict).

        Raises:
            AuthError: On invalid credentials or locked account.
        """
        user = UserRepository.get_by_email_or_username(identifier)

        # Use a timing-safe path that always hashes even when user not found,
        # preventing user enumeration through response timing differences.
        if user is None:
            verify_password(password, "$2b$12$invalidhashpadding000000000000000000000000000000000000000")
            raise AuthError("Invalid credentials", status_code=401)

        if not user.is_active:
            raise AuthError("Account has been deactivated", status_code=403)

        if user.is_locked():
            raise AuthError(
                f"Account is temporarily locked. Try again after {user.locked_until.isoformat()}",
                status_code=423,
            )

        if not verify_password(password, user.password_hash):
            AuthService._record_failed_login(user)
            raise AuthError("Invalid credentials", status_code=401)

        # Successful login — reset failure counters
        AuthService._record_successful_login(user)

        tokens = TokenService.issue_token_pair(user.id)
        return user, tokens

    @staticmethod
    def logout(jti: str) -> None:
        """
        Revoke the current access token by adding its JTI to the Redis blocklist.

        Args:
            jti: The 'jti' claim from the decoded JWT.
        """
        TokenService.revoke_token(jti)
        logger.info("User logged out, revoked jti=%s", jti)

    @staticmethod
    def refresh(jti: str, user_id: str) -> dict:
        """
        Issue a new access token from a valid refresh token.
        The old refresh token's JTI is revoked (token rotation).

        Args:
            jti: JTI of the refresh token being consumed.
            user_id: The user identity from the refresh token.

        Returns:
            New token pair dict.
        """
        # Revoke the consumed refresh token (rotation)
        refresh_ttl = int(
            current_app.config["JWT_REFRESH_TOKEN_EXPIRES"].total_seconds()
        )
        TokenService.revoke_token(jti, expires_in=refresh_ttl)

        user = UserRepository.get_by_id(user_id)
        if not user or not user.is_active:
            raise AuthError("User not found or inactive", status_code=401)

        return TokenService.issue_token_pair(user.id)

    @staticmethod
    def verify_email(token: str) -> User:
        """
        Mark an email address as verified using the one-time token.

        Args:
            token: The email verification token sent to the user.

        Returns:
            The updated User.

        Raises:
            AuthError: If the token is invalid or already used.
        """
        user = UserRepository.get_by_verification_token(token)
        if not user:
            raise AuthError("Invalid or expired verification token", status_code=400)
        if user.is_verified:
            raise AuthError("Email is already verified", status_code=400)

        user.is_verified = True
        user.email_verified_at = datetime.now(timezone.utc)
        user.email_verification_token = None
        UserRepository.save(user)

        logger.info("Email verified for user id=%s", user.id)
        return user

    @staticmethod
    def request_password_reset(email: str) -> Optional[str]:
        """
        Generate and store a password reset token.

        To prevent user enumeration, this always returns successfully even
        when the email is not found. The token is returned (for email delivery
        in a real implementation); None is returned if the user doesn't exist.

        Args:
            email: The account email address.

        Returns:
            The reset token string (to be emailed), or None.
        """
        email = validate_email(email)
        user = UserRepository.get_by_email(email)
        if not user:
            logger.debug("Password reset requested for unknown email %s", email)
            return None

        token = secrets.token_urlsafe(32)
        user.password_reset_token = token
        user.password_reset_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        UserRepository.save(user)

        logger.info("Password reset token issued for user id=%s", user.id)
        return token

    @staticmethod
    def reset_password(token: str, new_password: str) -> User:
        """
        Reset a user's password using a valid reset token.

        Args:
            token: The password reset token from the email link.
            new_password: The new plaintext password.

        Returns:
            The updated User.

        Raises:
            AuthError: If the token is invalid, expired, or already used.
            ValidationError: If the new password is invalid.
        """
        user = UserRepository.get_by_reset_token(token)
        if not user:
            raise AuthError("Invalid or expired reset token", status_code=400)

        if user.password_reset_expires_at < datetime.now(timezone.utc):
            user.password_reset_token = None
            user.password_reset_expires_at = None
            UserRepository.save(user)
            raise AuthError("Reset token has expired", status_code=400)

        validate_password(
            new_password,
            min_length=current_app.config["PASSWORD_MIN_LENGTH"],
            max_length=current_app.config["PASSWORD_MAX_LENGTH"],
        )

        user.password_hash = hash_password(new_password)
        user.password_reset_token = None
        user.password_reset_expires_at = None
        user.failed_login_attempts = 0
        user.locked_until = None
        UserRepository.save(user)

        logger.info("Password reset completed for user id=%s", user.id)
        return user

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _record_failed_login(user: User) -> None:
        """Increment the failure counter and lock the account if threshold reached."""
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= _MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.now(timezone.utc) + timedelta(
                minutes=_LOCKOUT_DURATION_MINUTES
            )
            logger.warning(
                "Account locked due to %d failed attempts: user_id=%s",
                user.failed_login_attempts,
                user.id,
            )
        UserRepository.save(user)

    @staticmethod
    def _record_successful_login(user: User) -> None:
        """Reset failure counters and record login metadata."""
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = datetime.now(timezone.utc)
        user.last_login_ip = request.remote_addr
        UserRepository.save(user)
