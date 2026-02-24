"""
OAuth 2.0 API

GET  /api/v1/oauth/authorize         — Authorization endpoint (show consent page)
POST /api/v1/oauth/authorize         — User grants/denies consent
POST /api/v1/oauth/token             — Token endpoint (all grant types)
POST /api/v1/oauth/token/revoke      — Revoke a token (RFC 7009)
POST /api/v1/oauth/token/introspect  — Token introspection (RFC 7662)
POST /api/v1/oauth/clients           — Register a new OAuth client
GET  /api/v1/oauth/clients           — List own clients
GET  /api/v1/oauth/clients/<id>      — Get a specific client
DELETE /api/v1/oauth/clients/<id>    — Delete a client
"""
import logging
from urllib.parse import urlencode

from flask import Blueprint, request, redirect
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.services.oauth_service import OAuthService, OAuthError
from app.repositories.oauth_repository import OAuthClientRepository
from app.utils.response import success_response, error_response
from app.utils.validators import ValidationError
from app.extensions import limiter

oauth_bp = Blueprint("oauth", __name__)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Authorization endpoint
# ---------------------------------------------------------------------------

@oauth_bp.get("/authorize")
@jwt_required()
def authorize_get():
    """
    Display the authorization consent page.

    In a real application this would render an HTML consent form.
    Here we return a JSON representation for API clients.
    ---
    tags:
      - OAuth 2.0
    security:
      - BearerAuth: []
    parameters:
      - in: query
        name: response_type
        required: true
        schema:
          type: string
          enum: [code]
      - in: query
        name: client_id
        required: true
        schema:
          type: string
      - in: query
        name: redirect_uri
        required: true
        schema:
          type: string
      - in: query
        name: scope
        schema:
          type: string
          default: read
      - in: query
        name: state
        schema:
          type: string
      - in: query
        name: code_challenge
        schema:
          type: string
      - in: query
        name: code_challenge_method
        schema:
          type: string
          enum: [S256, plain]
    responses:
      200:
        description: Consent information for display
      400:
        description: Invalid request parameters
    """
    response_type = request.args.get("response_type", "")
    client_id = request.args.get("client_id", "")
    redirect_uri = request.args.get("redirect_uri", "")
    scope = request.args.get("scope", "read")
    state = request.args.get("state")

    if response_type != "code":
        return error_response("Only response_type=code is supported", 400)
    if not client_id:
        return error_response("client_id is required", 400)
    if not redirect_uri:
        return error_response("redirect_uri is required", 400)

    client = OAuthClientRepository.get_by_client_id(client_id)
    if not client:
        return error_response("Unknown client_id", 400)
    if not client.is_redirect_uri_allowed(redirect_uri):
        return error_response("redirect_uri is not registered for this client", 400)

    return success_response(
        data={
            "client_name": client.client_name,
            "client_description": client.client_description,
            "requested_scopes": scope.split(),
            "redirect_uri": redirect_uri,
            "state": state,
        },
        message="Authorize the application to access your account",
    )


@oauth_bp.post("/authorize")
@jwt_required()
def authorize_post():
    """
    Process the user's authorization decision.

    The user must explicitly grant (action=allow) or deny (action=deny).
    On grant, an authorization code is issued and the client is redirected.
    ---
    tags:
      - OAuth 2.0
    security:
      - BearerAuth: []
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required: [action, client_id, redirect_uri, response_type]
            properties:
              action:
                type: string
                enum: [allow, deny]
              client_id:
                type: string
              redirect_uri:
                type: string
              response_type:
                type: string
                enum: [code]
              scope:
                type: string
              state:
                type: string
              nonce:
                type: string
              code_challenge:
                type: string
              code_challenge_method:
                type: string
    responses:
      302:
        description: Redirect to client with code or error
      400:
        description: Invalid request
    """
    user_id = get_jwt_identity()
    data = request.get_json(silent=True) or {}

    action = data.get("action", "")
    client_id = data.get("client_id", "")
    redirect_uri = data.get("redirect_uri", "")
    scope = data.get("scope", "read")
    state = data.get("state")

    if not redirect_uri:
        return error_response("redirect_uri is required", 400)

    # User denied access
    if action == "deny":
        params = {"error": "access_denied", "error_description": "User denied access"}
        if state:
            params["state"] = state
        return redirect(f"{redirect_uri}?{urlencode(params)}")

    if action != "allow":
        return error_response("action must be 'allow' or 'deny'", 400)

    try:
        auth_code = OAuthService.create_authorization_code(
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            nonce=data.get("nonce"),
            code_challenge=data.get("code_challenge"),
            code_challenge_method=data.get("code_challenge_method"),
        )
        params = {"code": auth_code.code}
        if state:
            params["state"] = state
        return redirect(f"{redirect_uri}?{urlencode(params)}")

    except OAuthError as exc:
        params = {"error": exc.error}
        if exc.description:
            params["error_description"] = exc.description
        if state:
            params["state"] = state
        return redirect(f"{redirect_uri}?{urlencode(params)}")


# ---------------------------------------------------------------------------
# Token endpoint
# ---------------------------------------------------------------------------

@oauth_bp.post("/token")
@limiter.limit("60 per minute")
def token():
    """
    OAuth 2.0 Token Endpoint — supports multiple grant types.

    Supported grant_type values:
      - authorization_code
      - client_credentials
      - refresh_token
    ---
    tags:
      - OAuth 2.0
    requestBody:
      required: true
      content:
        application/x-www-form-urlencoded:
          schema:
            type: object
            required: [grant_type]
            properties:
              grant_type:
                type: string
                enum: [authorization_code, client_credentials, refresh_token]
              code:
                type: string
              redirect_uri:
                type: string
              client_id:
                type: string
              client_secret:
                type: string
              refresh_token:
                type: string
              scope:
                type: string
              code_verifier:
                type: string
    responses:
      200:
        description: Token response
      400:
        description: Invalid request or grant
      401:
        description: Client authentication failed
    """
    # RFC 6749: token endpoint accepts both form-encoded and JSON
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form.to_dict()

    grant_type = data.get("grant_type", "")
    client_id = data.get("client_id", "")
    client_secret = data.get("client_secret")

    # Also support HTTP Basic auth for client credentials
    if request.authorization:
        client_id = client_id or request.authorization.username
        client_secret = client_secret or request.authorization.password

    try:
        if grant_type == "authorization_code":
            oauth_token = OAuthService.exchange_code_for_tokens(
                code_str=data.get("code", ""),
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=data.get("redirect_uri", ""),
                code_verifier=data.get("code_verifier"),
            )

        elif grant_type == "client_credentials":
            oauth_token = OAuthService.client_credentials(
                client_id=client_id,
                client_secret=client_secret or "",
                scope=data.get("scope"),
            )

        elif grant_type == "refresh_token":
            oauth_token = OAuthService.refresh_token(
                refresh_token_str=data.get("refresh_token", ""),
                client_id=client_id,
                client_secret=client_secret,
            )

        else:
            return (
                _oauth_error("unsupported_grant_type", f"'{grant_type}' is not supported"),
                400,
            )

        return _oauth_token_response(oauth_token)

    except OAuthError as exc:
        logger.warning("OAuth token error: %s — %s", exc.error, exc.description)
        return _oauth_error(exc.error, exc.description), exc.status_code


# ---------------------------------------------------------------------------
# Token revocation (RFC 7009)
# ---------------------------------------------------------------------------

@oauth_bp.post("/token/revoke")
def token_revoke():
    """
    Revoke an access or refresh token.
    ---
    tags:
      - OAuth 2.0
    requestBody:
      required: true
      content:
        application/x-www-form-urlencoded:
          schema:
            type: object
            required: [token]
            properties:
              token:
                type: string
              client_id:
                type: string
              client_secret:
                type: string
    responses:
      200:
        description: Token revoked (RFC 7009 — always 200)
    """
    data = request.form.to_dict() if not request.is_json else (request.get_json(silent=True) or {})
    try:
        OAuthService.revoke_token(
            token_str=data.get("token", ""),
            client_id=data.get("client_id", ""),
            client_secret=data.get("client_secret"),
        )
    except OAuthError:
        pass  # Per RFC 7009, always return 200
    return success_response(message="Token revoked")


# ---------------------------------------------------------------------------
# Token introspection (RFC 7662)
# ---------------------------------------------------------------------------

@oauth_bp.post("/token/introspect")
def token_introspect():
    """
    Introspect a token and return its metadata.
    ---
    tags:
      - OAuth 2.0
    requestBody:
      required: true
      content:
        application/x-www-form-urlencoded:
          schema:
            type: object
            required: [token, client_id, client_secret]
            properties:
              token:
                type: string
              client_id:
                type: string
              client_secret:
                type: string
    responses:
      200:
        description: Token introspection response
      401:
        description: Client authentication failed
    """
    data = request.form.to_dict() if not request.is_json else (request.get_json(silent=True) or {})
    try:
        result = OAuthService.introspect_token(
            token_str=data.get("token", ""),
            client_id=data.get("client_id", ""),
            client_secret=data.get("client_secret"),
        )
        return success_response(data=result)
    except OAuthError as exc:
        return _oauth_error(exc.error, exc.description), exc.status_code


# ---------------------------------------------------------------------------
# Client management
# ---------------------------------------------------------------------------

@oauth_bp.post("/clients")
@jwt_required()
def register_client():
    """
    Register a new OAuth 2.0 client application.
    ---
    tags:
      - OAuth Clients
    security:
      - BearerAuth: []
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required: [client_name, redirect_uris]
            properties:
              client_name:
                type: string
              redirect_uris:
                type: array
                items:
                  type: string
              grant_types:
                type: array
                items:
                  type: string
              scope:
                type: string
                default: read
              client_type:
                type: string
                enum: [confidential, public]
                default: confidential
              client_description:
                type: string
              client_uri:
                type: string
    responses:
      201:
        description: Client registered (includes one-time client_secret)
      400:
        description: Validation error
    """
    user_id = get_jwt_identity()
    data = request.get_json(silent=True) or {}

    client_name = data.get("client_name", "").strip()
    redirect_uris = data.get("redirect_uris", [])

    if not client_name:
        return error_response("client_name is required", 400)
    if not redirect_uris or not isinstance(redirect_uris, list):
        return error_response("redirect_uris must be a non-empty list", 400)

    try:
        client, plaintext_secret = OAuthService.register_client(
            client_name=client_name,
            redirect_uris=redirect_uris,
            owner_id=user_id,
            grant_types=data.get("grant_types"),
            scope=data.get("scope", "read"),
            client_type=data.get("client_type", "confidential"),
            client_description=data.get("client_description"),
            client_uri=data.get("client_uri"),
        )
        response_data = client.to_dict()
        if plaintext_secret:
            # Return exactly once — not stored in plaintext
            response_data["client_secret"] = plaintext_secret
        return success_response(
            data=response_data,
            message="Client registered. Store the client_secret securely — it won't be shown again.",
            status_code=201,
        )
    except OAuthError as exc:
        return error_response(exc.description or exc.error, exc.status_code)


@oauth_bp.get("/clients")
@jwt_required()
def list_clients():
    """
    List OAuth clients owned by the current user.
    ---
    tags:
      - OAuth Clients
    security:
      - BearerAuth: []
    responses:
      200:
        description: List of owned clients
    """
    user_id = get_jwt_identity()
    clients = OAuthClientRepository.list_by_owner(user_id)
    return success_response(data=[c.to_dict() for c in clients])


@oauth_bp.get("/clients/<client_pk>")
@jwt_required()
def get_client(client_pk: str):
    """
    Get a specific OAuth client by its primary key.
    ---
    tags:
      - OAuth Clients
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: client_pk
        required: true
        schema:
          type: string
    responses:
      200:
        description: Client details
      403:
        description: Not the client owner
      404:
        description: Client not found
    """
    user_id = get_jwt_identity()
    client = OAuthClientRepository.get_by_id(client_pk)
    if not client:
        return error_response("Client not found", 404)
    if client.owner_id != user_id:
        return error_response("Access denied", 403)
    return success_response(data=client.to_dict())


@oauth_bp.delete("/clients/<client_pk>")
@jwt_required()
def delete_client(client_pk: str):
    """
    Delete an OAuth client.
    ---
    tags:
      - OAuth Clients
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: client_pk
        required: true
        schema:
          type: string
    responses:
      200:
        description: Client deleted
      403:
        description: Not the client owner
      404:
        description: Client not found
    """
    user_id = get_jwt_identity()
    client = OAuthClientRepository.get_by_id(client_pk)
    if not client:
        return error_response("Client not found", 404)
    if client.owner_id != user_id:
        return error_response("Access denied", 403)

    OAuthClientRepository.delete(client)
    return success_response(message="Client deleted")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _oauth_token_response(token):
    """Return an RFC 6749-compliant token response."""
    from flask import jsonify
    return jsonify(token.to_dict()), 200


def _oauth_error(error: str, description: str = None):
    """Return an RFC 6749-compliant error response."""
    from flask import jsonify
    body = {"error": error}
    if description:
        body["error_description"] = description
    return jsonify(body)
