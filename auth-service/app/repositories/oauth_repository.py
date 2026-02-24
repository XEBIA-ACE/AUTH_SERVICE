"""
OAuth Repository — Data Access Layer

Handles persistence for OAuthClient, OAuthToken, and OAuthAuthorizationCode.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from app.extensions import db
from app.models.oauth_client import OAuthClient
from app.models.oauth_token import OAuthToken
from app.models.oauth_authorization_code import OAuthAuthorizationCode

logger = logging.getLogger(__name__)


class OAuthClientRepository:

    @staticmethod
    def get_by_id(client_id: str) -> Optional[OAuthClient]:
        return db.session.get(OAuthClient, client_id)

    @staticmethod
    def get_by_client_id(client_id: str) -> Optional[OAuthClient]:
        return OAuthClient.query.filter_by(client_id=client_id, is_active=True).first()

    @staticmethod
    def list_by_owner(owner_id: str) -> list[OAuthClient]:
        return OAuthClient.query.filter_by(owner_id=owner_id).order_by(
            OAuthClient.created_at.desc()
        ).all()

    @staticmethod
    def create(
        client_name: str,
        redirect_uris: list[str],
        owner_id: str,
        grant_types: list[str] = None,
        response_types: list[str] = None,
        scope: str = "read",
        client_type: str = "confidential",
        client_description: str = None,
        client_uri: str = None,
    ) -> OAuthClient:
        client = OAuthClient(
            client_name=client_name,
            redirect_uris="\n".join(redirect_uris),
            owner_id=owner_id,
            grant_types=" ".join(grant_types or ["authorization_code"]),
            response_types=" ".join(response_types or ["code"]),
            scope=scope,
            client_type=client_type,
            client_description=client_description,
            client_uri=client_uri,
        )
        db.session.add(client)
        db.session.commit()
        logger.info("Created OAuth client id=%s name=%s", client.client_id, client.client_name)
        return client

    @staticmethod
    def save(client: OAuthClient) -> OAuthClient:
        db.session.add(client)
        db.session.commit()
        return client

    @staticmethod
    def delete(client: OAuthClient) -> None:
        db.session.delete(client)
        db.session.commit()


class OAuthTokenRepository:

    @staticmethod
    def get_by_access_token(access_token: str) -> Optional[OAuthToken]:
        return OAuthToken.query.filter_by(
            access_token=access_token, is_revoked=False
        ).first()

    @staticmethod
    def get_by_refresh_token(refresh_token: str) -> Optional[OAuthToken]:
        return OAuthToken.query.filter_by(
            refresh_token=refresh_token, is_revoked=False
        ).first()

    @staticmethod
    def create(
        access_token: str,
        user_id: str,
        client_id: str,
        scope: str,
        access_token_expires_at: datetime,
        refresh_token: str = None,
        refresh_token_expires_at: datetime = None,
    ) -> OAuthToken:
        token = OAuthToken(
            access_token=access_token,
            refresh_token=refresh_token,
            user_id=user_id,
            client_id=client_id,
            scope=scope,
            access_token_expires_at=access_token_expires_at,
            refresh_token_expires_at=refresh_token_expires_at,
        )
        db.session.add(token)
        db.session.commit()
        return token

    @staticmethod
    def revoke_all_for_user(user_id: str) -> int:
        """Revoke all active tokens for a user (e.g., on password change)."""
        now = datetime.now(timezone.utc)
        count = OAuthToken.query.filter_by(
            user_id=user_id, is_revoked=False
        ).update({"is_revoked": True, "revoked_at": now})
        db.session.commit()
        logger.info("Revoked %d tokens for user_id=%s", count, user_id)
        return count

    @staticmethod
    def save(token: OAuthToken) -> OAuthToken:
        db.session.add(token)
        db.session.commit()
        return token

    @staticmethod
    def cleanup_expired(older_than_days: int = 7) -> int:
        """Delete revoked/expired tokens older than the given number of days."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
        count = OAuthToken.query.filter(
            (OAuthToken.is_revoked == True) | (OAuthToken.access_token_expires_at < cutoff)
        ).filter(OAuthToken.created_at < cutoff).delete()
        db.session.commit()
        return count


class OAuthAuthorizationCodeRepository:

    @staticmethod
    def get_by_code(code: str) -> Optional[OAuthAuthorizationCode]:
        return OAuthAuthorizationCode.query.filter_by(code=code).first()

    @staticmethod
    def create(
        user_id: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        expires_at: datetime,
        state: str = None,
        nonce: str = None,
        code_challenge: str = None,
        code_challenge_method: str = None,
    ) -> OAuthAuthorizationCode:
        auth_code = OAuthAuthorizationCode(
            user_id=user_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            expires_at=expires_at,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    @staticmethod
    def save(code: OAuthAuthorizationCode) -> OAuthAuthorizationCode:
        db.session.add(code)
        db.session.commit()
        return code

    @staticmethod
    def cleanup_expired() -> int:
        """Delete used or expired authorization codes."""
        now = datetime.now(timezone.utc)
        count = OAuthAuthorizationCode.query.filter(
            (OAuthAuthorizationCode.is_used == True)
            | (OAuthAuthorizationCode.expires_at < now)
        ).delete()
        db.session.commit()
        return count
