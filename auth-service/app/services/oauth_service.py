"""
OAuth 2.0 Service — Authorization flows and token management.

Implements:
  • Authorization Code Flow (with optional PKCE — RFC 7636)
  • Client Credentials Flow
  • Refresh Token rotation
  • Token introspection (RFC 7662)
  • Token revocation (RFC 7009)
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from flask import current_app

from app.models.oauth_client import OAuthClient
from app.models.oauth_token import OAuthToken
from app.models.oauth_authorization_code import OAuthAuthorizationCode
from app.repositories.oauth_repository import (
    OAuthClientRepository,
    OAuthTokenRepository,
    OAuthAuthorizationCodeRepository,
)
from app.utils.security import (
    hash_secret,
    verify_secret,
    verify_pkce_challenge,
    generate_opaque_token,
)
from app.utils.validators import ValidationError

logger = logging.getLogger(__name__)


class OAuthError(Exception):
    """RFC 6749-compliant OAuth error."""

    def __init__(self, error: str, description: str = None, status_code: int = 400):
        self.error = error
        self.description = description
        self.status_code = status_code
        super().__init__(description or error)

    def to_dict(self) -> dict:
        d = {"error": self.error}
        if self.description:
            d["error_description"] = self.description
        return d


class OAuthService:
    """Implements the OAuth 2.0 server-side flows."""

    # ------------------------------------------------------------------
    # Client management
    # ------------------------------------------------------------------

    @staticmethod
    def register_client(
        client_name: str,
        redirect_uris: list[str],
        owner_id: str,
        grant_types: list[str] = None,
        response_types: list[str] = None,
        scope: str = "read",
        client_type: str = "confidential",
        client_description: str = None,
        client_uri: str = None,
    ) -> tuple[OAuthClient, Optional[str]]:
        """
        Register a new OAuth client application.

        Returns:
            Tuple of (OAuthClient, plaintext_secret).
            The plaintext_secret is returned exactly once and must be stored by the caller.
            Only confidential clients receive a secret.
        """
        grant_types = grant_types or ["authorization_code"]
        response_types = response_types or ["code"]

        client = OAuthClientRepository.create(
            client_name=client_name,
            redirect_uris=redirect_uris,
            owner_id=owner_id,
            grant_types=grant_types,
            response_types=response_types,
            scope=scope,
            client_type=client_type,
            client_description=client_description,
            client_uri=client_uri,
        )

        plaintext_secret = None
        if client_type == "confidential":
            plaintext_secret = secrets.token_urlsafe(32)
            client.client_secret_hash = hash_secret(plaintext_secret)
            OAuthClientRepository.save(client)

        logger.info(
            "Registered OAuth client client_id=%s type=%s", client.client_id, client_type
        )
        return client, plaintext_secret

    @staticmethod
    def authenticate_client(
        client_id: str, client_secret: Optional[str]
    ) -> OAuthClient:
        """
        Authenticate an OAuth client by ID + secret.

        Raises:
            OAuthError: On invalid_client.
        """
        client = OAuthClientRepository.get_by_client_id(client_id)
        if not client:
            raise OAuthError("invalid_client", "Client not found")

        if client.client_type == "confidential":
            if not client_secret:
                raise OAuthError("invalid_client", "Client secret is required")
            if not client.client_secret_hash or not verify_secret(
                client_secret, client.client_secret_hash
            ):
                raise OAuthError("invalid_client", "Invalid client secret")

        return client

    # ------------------------------------------------------------------
    # Authorization Code Flow
    # ------------------------------------------------------------------

    @staticmethod
    def create_authorization_code(
        client_id: str,
        user_id: str,
        redirect_uri: str,
        scope: str,
        state: Optional[str] = None,
        nonce: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
    ) -> OAuthAuthorizationCode:
        """
        Issue a short-lived authorization code after the user grants consent.

        Args:
            client_id: The OAuth client's client_id (not PK).
            user_id: The authenticated user granting access.
            redirect_uri: The URI to redirect to with the code.
            scope: Space-separated scopes being granted.
            state: CSRF-protection state value (should be validated by caller).
            nonce: OpenID Connect nonce.
            code_challenge: PKCE challenge (optional but recommended for public clients).
            code_challenge_method: "S256" or "plain".

        Returns:
            The newly created OAuthAuthorizationCode.
        """
        client = OAuthClientRepository.get_by_client_id(client_id)
        if not client:
            raise OAuthError("invalid_client", "Unknown client")

        if not client.is_redirect_uri_allowed(redirect_uri):
            raise OAuthError("invalid_request", "redirect_uri is not registered for this client")

        if not client.is_grant_type_allowed("authorization_code"):
            raise OAuthError("unauthorized_client", "Client is not allowed to use authorization_code grant")

        if scope and not client.is_scope_allowed(scope):
            raise OAuthError("invalid_scope", f"One or more requested scopes are not allowed")

        ttl = current_app.config["OAUTH_AUTHORIZATION_CODE_EXPIRES"]
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)

        code = OAuthAuthorizationCodeRepository.create(
            user_id=user_id,
            client_id=client.id,
            redirect_uri=redirect_uri,
            scope=scope or client.scope,
            expires_at=expires_at,
            state=state,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        return code

    @staticmethod
    def exchange_code_for_tokens(
        code_str: str,
        client_id: str,
        client_secret: Optional[str],
        redirect_uri: str,
        code_verifier: Optional[str] = None,
    ) -> OAuthToken:
        """
        Exchange an authorization code for access + refresh tokens.

        Args:
            code_str: The authorization code value.
            client_id: OAuth client_id string.
            client_secret: OAuth client secret (for confidential clients).
            redirect_uri: Must match the URI used when requesting the code.
            code_verifier: PKCE verifier (required if code was issued with a challenge).

        Returns:
            The newly issued OAuthToken.

        Raises:
            OAuthError: On any validation failure.
        """
        client = OAuthService.authenticate_client(client_id, client_secret)

        auth_code = OAuthAuthorizationCodeRepository.get_by_code(code_str)
        if not auth_code or not auth_code.is_valid():
            raise OAuthError("invalid_grant", "Authorization code is invalid or expired")

        if auth_code.client_id != client.id:
            raise OAuthError("invalid_grant", "Code was not issued to this client")

        if auth_code.redirect_uri != redirect_uri:
            raise OAuthError("invalid_grant", "redirect_uri does not match")

        # Verify PKCE if the code was issued with a challenge
        if auth_code.code_challenge:
            if not code_verifier:
                raise OAuthError("invalid_grant", "code_verifier is required")
            if not verify_pkce_challenge(
                code_verifier, auth_code.code_challenge, auth_code.code_challenge_method
            ):
                raise OAuthError("invalid_grant", "code_verifier does not match code_challenge")

        # Mark code as consumed before issuing tokens (prevents replay)
        auth_code.mark_used()
        OAuthAuthorizationCodeRepository.save(auth_code)

        return OAuthService._issue_token(
            user_id=auth_code.user_id,
            client=client,
            scope=auth_code.scope,
            include_refresh=True,
        )

    # ------------------------------------------------------------------
    # Client Credentials Flow
    # ------------------------------------------------------------------

    @staticmethod
    def client_credentials(
        client_id: str,
        client_secret: str,
        scope: str = None,
    ) -> OAuthToken:
        """
        Issue a machine-to-machine access token using the Client Credentials grant.
        No user is involved; the token is issued on behalf of the client itself.

        Args:
            client_id: OAuth client_id.
            client_secret: OAuth client secret (required — only confidential clients allowed).
            scope: Requested scope (must be a subset of the client's allowed scopes).

        Returns:
            The issued OAuthToken.
        """
        client = OAuthService.authenticate_client(client_id, client_secret)

        if not client.is_grant_type_allowed("client_credentials"):
            raise OAuthError(
                "unauthorized_client",
                "Client is not authorized for client_credentials grant",
            )

        if scope and not client.is_scope_allowed(scope):
            raise OAuthError("invalid_scope", "Requested scope is not allowed")

        # For client_credentials, user_id = the owner of the client
        return OAuthService._issue_token(
            user_id=client.owner_id,
            client=client,
            scope=scope or client.scope,
            include_refresh=False,  # Refresh tokens are not issued for client_credentials
        )

    # ------------------------------------------------------------------
    # Refresh Token
    # ------------------------------------------------------------------

    @staticmethod
    def refresh_token(
        refresh_token_str: str,
        client_id: str,
        client_secret: Optional[str],
    ) -> OAuthToken:
        """
        Rotate a refresh token: revoke the old one and issue a new token pair.

        Args:
            refresh_token_str: The refresh token to exchange.
            client_id: OAuth client_id.
            client_secret: OAuth client secret.

        Returns:
            The new OAuthToken.
        """
        client = OAuthService.authenticate_client(client_id, client_secret)

        old_token = OAuthTokenRepository.get_by_refresh_token(refresh_token_str)
        if not old_token:
            raise OAuthError("invalid_grant", "Refresh token is invalid or expired")

        if old_token.client_id != client.id:
            raise OAuthError("invalid_grant", "Token was not issued to this client")

        if old_token.is_refresh_token_expired:
            raise OAuthError("invalid_grant", "Refresh token has expired")

        # Revoke the old token pair
        old_token.revoke()
        OAuthTokenRepository.save(old_token)

        return OAuthService._issue_token(
            user_id=old_token.user_id,
            client=client,
            scope=old_token.scope,
            include_refresh=True,
        )

    # ------------------------------------------------------------------
    # Token introspection (RFC 7662)
    # ------------------------------------------------------------------

    @staticmethod
    def introspect_token(
        token_str: str,
        client_id: str,
        client_secret: Optional[str],
    ) -> dict:
        """
        Return metadata about an access token.

        Returns a dict with 'active' = True/False per RFC 7662.
        """
        OAuthService.authenticate_client(client_id, client_secret)

        token = OAuthTokenRepository.get_by_access_token(token_str)
        if not token or token.is_revoked or token.is_access_token_expired:
            return {"active": False}

        return {
            "active": True,
            "scope": token.scope,
            "client_id": token.client.client_id,
            "username": token.user.username if token.user else None,
            "sub": token.user_id,
            "exp": int(token.access_token_expires_at.timestamp()),
            "iat": int(token.created_at.timestamp()),
            "token_type": token.token_type,
        }

    # ------------------------------------------------------------------
    # Token revocation (RFC 7009)
    # ------------------------------------------------------------------

    @staticmethod
    def revoke_token(
        token_str: str,
        client_id: str,
        client_secret: Optional[str],
    ) -> None:
        """
        Revoke an access or refresh token.
        Per RFC 7009, always returns 200 even if the token does not exist.
        """
        OAuthService.authenticate_client(client_id, client_secret)

        token = OAuthTokenRepository.get_by_access_token(
            token_str
        ) or OAuthTokenRepository.get_by_refresh_token(token_str)

        if token:
            token.revoke()
            OAuthTokenRepository.save(token)
            logger.info("OAuth token revoked for user_id=%s", token.user_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _issue_token(
        user_id: str,
        client: OAuthClient,
        scope: str,
        include_refresh: bool = True,
    ) -> OAuthToken:
        """Create and persist a new OAuthToken record."""
        now = datetime.now(timezone.utc)
        access_ttl = current_app.config["OAUTH_ACCESS_TOKEN_EXPIRES"]
        refresh_ttl = current_app.config["OAUTH_REFRESH_TOKEN_EXPIRES"]

        access_token_str = generate_opaque_token()
        refresh_token_str = generate_opaque_token() if include_refresh else None

        token = OAuthTokenRepository.create(
            access_token=access_token_str,
            refresh_token=refresh_token_str,
            user_id=user_id,
            client_id=client.id,
            scope=scope,
            access_token_expires_at=now + timedelta(seconds=access_ttl),
            refresh_token_expires_at=(now + timedelta(seconds=refresh_ttl)) if include_refresh else None,
        )
        logger.info(
            "Issued OAuth token for user_id=%s client=%s scope='%s'",
            user_id,
            client.client_id,
            scope,
        )
        return token
