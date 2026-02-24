"""
Token Service — JWT lifecycle management.

Handles issuing, refreshing, and revoking JWT access/refresh tokens.
Redis is used as a blocklist backend so revoked tokens are rejected
immediately (rather than waiting for natural expiry).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

import redis
from flask import current_app
from flask_jwt_extended import create_access_token, create_refresh_token, decode_token

logger = logging.getLogger(__name__)

# Module-level Redis client — lazy-initialized on first use
_redis_client: Optional[redis.Redis] = None


def _get_redis() -> redis.Redis:
    """Return (and lazily create) the Redis client."""
    global _redis_client
    if _redis_client is None:
        url = current_app.config.get("REDIS_URL", "redis://localhost:6379/0")
        _redis_client = redis.from_url(url, decode_responses=True)
    return _redis_client


class TokenService:
    """JWT creation, validation, and revocation logic."""

    # Redis key prefix for blocklisted JTIs
    _BLOCKLIST_PREFIX = "jwt:revoked:"

    @classmethod
    def issue_access_token(cls, user_id: str, extra_claims: dict = None) -> str:
        """Issue a new JWT access token for a user."""
        return create_access_token(
            identity=user_id,
            additional_claims=extra_claims or {},
        )

    @classmethod
    def issue_refresh_token(cls, user_id: str) -> str:
        """Issue a new JWT refresh token for a user."""
        return create_refresh_token(identity=user_id)

    @classmethod
    def issue_token_pair(cls, user_id: str) -> dict:
        """
        Issue both an access token and a refresh token.

        Returns:
            Dict with 'access_token', 'refresh_token', 'token_type', and 'expires_in'.
        """
        access_token = cls.issue_access_token(user_id)
        refresh_token = cls.issue_refresh_token(user_id)
        expires_in = int(
            current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()
        )
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": expires_in,
        }

    @classmethod
    def revoke_token(cls, jti: str, expires_in: int = None) -> None:
        """
        Add a JTI to the Redis blocklist.

        Args:
            jti: The JWT ID claim from the token to revoke.
            expires_in: Seconds until the entry auto-expires from Redis.
                        Defaults to the access token TTL from config.
        """
        if expires_in is None:
            expires_in = int(
                current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()
            )
        key = f"{cls._BLOCKLIST_PREFIX}{jti}"
        try:
            _get_redis().setex(key, expires_in, "revoked")
            logger.debug("Revoked token jti=%s", jti)
        except redis.RedisError as exc:
            logger.error("Failed to revoke token jti=%s: %s", jti, exc)
            raise

    @classmethod
    def is_token_revoked(cls, jti: str) -> bool:
        """
        Return True if the given JTI has been blocklisted in Redis.
        Falls back to False if Redis is unavailable (fail-open for availability).
        """
        try:
            return _get_redis().exists(f"{cls._BLOCKLIST_PREFIX}{jti}") > 0
        except redis.RedisError as exc:
            logger.warning("Redis unavailable during token check: %s", exc)
            return False

    @classmethod
    def decode_token_payload(cls, token: str) -> Optional[dict]:
        """
        Decode and return the payload of a JWT without verifying expiry.
        Used internally for refresh flows.
        """
        try:
            return decode_token(token, allow_expired=True)
        except Exception as exc:
            logger.debug("Failed to decode token: %s", exc)
            return None
