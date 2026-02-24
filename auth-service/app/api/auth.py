"""
Authentication API

POST /api/v1/auth/register       — Create a new account
POST /api/v1/auth/login          — Authenticate and get JWT tokens
POST /api/v1/auth/logout         — Revoke current access token
POST /api/v1/auth/refresh        — Rotate refresh token for a new access token
POST /api/v1/auth/verify-email   — Confirm email address
POST /api/v1/auth/forgot-password  — Request a password reset link
POST /api/v1/auth/reset-password   — Set a new password via reset token
"""
import logging

from flask import Blueprint, request
from flask_jwt_extended import (
    get_jwt,
    get_jwt_identity,
    jwt_required,
)

from app.services.auth_service import AuthService, AuthError
from app.utils.response import success_response, error_response
from app.utils.validators import ValidationError
from app.extensions import limiter

auth_bp = Blueprint("auth", __name__)
logger = logging.getLogger(__name__)


@auth_bp.post("/register")
@limiter.limit("10 per hour")
def register():
    """
    Register a new user account.
    ---
    tags:
      - Authentication
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required: [email, username, password]
            properties:
              email:
                type: string
                format: email
                example: alice@example.com
              username:
                type: string
                example: alice
              password:
                type: string
                format: password
                example: SecureP@ss1
              first_name:
                type: string
                example: Alice
              last_name:
                type: string
                example: Smith
    responses:
      201:
        description: Account created successfully
      400:
        description: Validation error
      409:
        description: Email or username already exists
    """
    data = request.get_json(silent=True) or {}

    try:
        user = AuthService.register(
            email=data.get("email", ""),
            username=data.get("username", ""),
            password=data.get("password", ""),
            first_name=data.get("first_name"),
            last_name=data.get("last_name"),
        )
        return success_response(
            data=user.to_dict(),
            message="Account created. Please verify your email.",
            status_code=201,
        )
    except ValidationError as exc:
        return error_response(exc.message, 400, {"field": exc.field})
    except AuthError as exc:
        return error_response(exc.message, exc.status_code)


@auth_bp.post("/login")
@limiter.limit("20 per minute")
def login():
    """
    Authenticate and receive JWT access + refresh tokens.
    ---
    tags:
      - Authentication
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required: [identifier, password]
            properties:
              identifier:
                type: string
                description: Email address or username
                example: alice@example.com
              password:
                type: string
                format: password
                example: SecureP@ss1
    responses:
      200:
        description: Login successful
      401:
        description: Invalid credentials
      423:
        description: Account temporarily locked
    """
    data = request.get_json(silent=True) or {}

    try:
        user, tokens = AuthService.login(
            identifier=data.get("identifier", ""),
            password=data.get("password", ""),
        )
        logger.info("Login successful for user_id=%s", user.id)
        return success_response(
            data={
                "user": user.to_dict(),
                "tokens": tokens,
            },
            message="Login successful",
        )
    except AuthError as exc:
        logger.warning("Failed login attempt for identifier=%s", data.get("identifier"))
        return error_response(exc.message, exc.status_code)


@auth_bp.post("/logout")
@jwt_required()
def logout():
    """
    Revoke the current access token.
    ---
    tags:
      - Authentication
    security:
      - BearerAuth: []
    responses:
      200:
        description: Logged out successfully
      401:
        description: Missing or invalid token
    """
    jti = get_jwt()["jti"]
    AuthService.logout(jti)
    return success_response(message="Logged out successfully")


@auth_bp.post("/refresh")
@jwt_required(refresh=True)
def refresh():
    """
    Exchange a refresh token for a new access token pair (token rotation).
    ---
    tags:
      - Authentication
    security:
      - BearerAuth: []
    responses:
      200:
        description: New token pair issued
      401:
        description: Invalid or expired refresh token
    """
    jti = get_jwt()["jti"]
    user_id = get_jwt_identity()

    try:
        tokens = AuthService.refresh(jti=jti, user_id=user_id)
        return success_response(data=tokens, message="Token refreshed")
    except AuthError as exc:
        return error_response(exc.message, exc.status_code)


@auth_bp.post("/verify-email")
@limiter.limit("10 per hour")
def verify_email():
    """
    Verify an email address using the token sent by email.
    ---
    tags:
      - Authentication
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required: [token]
            properties:
              token:
                type: string
                example: abc123xyz
    responses:
      200:
        description: Email verified successfully
      400:
        description: Invalid or already-used token
    """
    data = request.get_json(silent=True) or {}
    token = data.get("token", "").strip()

    if not token:
        return error_response("Verification token is required", 400)

    try:
        user = AuthService.verify_email(token)
        return success_response(data=user.to_dict(), message="Email verified successfully")
    except AuthError as exc:
        return error_response(exc.message, exc.status_code)


@auth_bp.post("/forgot-password")
@limiter.limit("5 per hour")
def forgot_password():
    """
    Request a password reset link (sent to the registered email).
    Always returns 200 to prevent user enumeration.
    ---
    tags:
      - Authentication
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required: [email]
            properties:
              email:
                type: string
                format: email
                example: alice@example.com
    responses:
      200:
        description: Reset instructions sent if the account exists
    """
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")

    try:
        reset_token = AuthService.request_password_reset(email)
        # In production: email the reset_token to the user here
        if reset_token:
            logger.info("Password reset token generated (would be emailed)")
    except ValidationError:
        pass  # Swallow validation errors to prevent enumeration

    return success_response(
        message="If an account with that email exists, reset instructions have been sent."
    )


@auth_bp.post("/reset-password")
@limiter.limit("10 per hour")
def reset_password():
    """
    Set a new password using a valid reset token.
    ---
    tags:
      - Authentication
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required: [token, new_password]
            properties:
              token:
                type: string
                example: reset_token_here
              new_password:
                type: string
                format: password
                example: NewSecureP@ss1
    responses:
      200:
        description: Password reset successfully
      400:
        description: Invalid or expired token, or weak password
    """
    data = request.get_json(silent=True) or {}

    try:
        user = AuthService.reset_password(
            token=data.get("token", ""),
            new_password=data.get("new_password", ""),
        )
        return success_response(data=user.to_dict(), message="Password reset successfully")
    except (AuthError, ValidationError) as exc:
        msg = exc.message if hasattr(exc, "message") else str(exc)
        code = exc.status_code if hasattr(exc, "status_code") else 400
        return error_response(msg, code)
