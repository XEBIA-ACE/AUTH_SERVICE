"""
Users API

GET    /api/v1/users/me              — Get current user profile
PUT    /api/v1/users/me              — Update current user profile
POST   /api/v1/users/me/change-password — Change password
DELETE /api/v1/users/me             — Deactivate own account
GET    /api/v1/users                 — List users (superuser only)
GET    /api/v1/users/<id>            — Get user by ID (superuser only)
"""
import logging

from flask import Blueprint, request
from flask_jwt_extended import get_jwt_identity, jwt_required, get_jwt

from app.services.user_service import UserService
from app.services.auth_service import AuthError
from app.utils.response import success_response, error_response, paginated_response
from app.utils.validators import ValidationError

users_bp = Blueprint("users", __name__)
logger = logging.getLogger(__name__)


def _require_superuser():
    """Helper: raise 403 if the current JWT user is not a superuser."""
    from app.repositories.user_repository import UserRepository
    user_id = get_jwt_identity()
    user = UserRepository.get_by_id(user_id)
    if not user or not user.is_superuser:
        raise AuthError("Superuser access required", status_code=403)
    return user


@users_bp.get("/me")
@jwt_required()
def get_me():
    """
    Get the authenticated user's own profile.
    ---
    tags:
      - Users
    security:
      - BearerAuth: []
    responses:
      200:
        description: Current user profile
      401:
        description: Unauthorized
    """
    user_id = get_jwt_identity()
    try:
        user = UserService.get_user(user_id)
        return success_response(data=user.to_dict())
    except AuthError as exc:
        return error_response(exc.message, exc.status_code)


@users_bp.put("/me")
@jwt_required()
def update_me():
    """
    Update the current user's profile fields.
    ---
    tags:
      - Users
    security:
      - BearerAuth: []
    requestBody:
      content:
        application/json:
          schema:
            type: object
            properties:
              username:
                type: string
              first_name:
                type: string
              last_name:
                type: string
    responses:
      200:
        description: Profile updated
      400:
        description: Validation error
      409:
        description: Username already taken
    """
    user_id = get_jwt_identity()
    data = request.get_json(silent=True) or {}

    try:
        user = UserService.update_profile(
            user_id=user_id,
            first_name=data.get("first_name"),
            last_name=data.get("last_name"),
            username=data.get("username"),
        )
        return success_response(data=user.to_dict(), message="Profile updated")
    except (AuthError, ValidationError) as exc:
        msg = exc.message if hasattr(exc, "message") else str(exc)
        code = exc.status_code if hasattr(exc, "status_code") else 400
        return error_response(msg, code)


@users_bp.post("/me/change-password")
@jwt_required()
def change_password():
    """
    Change the current user's password.
    ---
    tags:
      - Users
    security:
      - BearerAuth: []
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            required: [current_password, new_password]
            properties:
              current_password:
                type: string
                format: password
              new_password:
                type: string
                format: password
    responses:
      200:
        description: Password changed
      400:
        description: Incorrect current password or weak new password
    """
    user_id = get_jwt_identity()
    data = request.get_json(silent=True) or {}

    try:
        UserService.change_password(
            user_id=user_id,
            current_password=data.get("current_password", ""),
            new_password=data.get("new_password", ""),
        )
        return success_response(message="Password changed successfully")
    except (AuthError, ValidationError) as exc:
        msg = exc.message if hasattr(exc, "message") else str(exc)
        code = exc.status_code if hasattr(exc, "status_code") else 400
        return error_response(msg, code)


@users_bp.delete("/me")
@jwt_required()
def deactivate_me():
    """
    Deactivate the current user's own account.
    ---
    tags:
      - Users
    security:
      - BearerAuth: []
    responses:
      200:
        description: Account deactivated
    """
    user_id = get_jwt_identity()
    try:
        user = UserService.deactivate(
            user_id=user_id,
            requesting_user_id=user_id,
            is_superuser=False,
        )
        return success_response(message="Account deactivated")
    except AuthError as exc:
        return error_response(exc.message, exc.status_code)


# ------------------------------------------------------------------
# Admin endpoints (superuser only)
# ------------------------------------------------------------------

@users_bp.get("")
@jwt_required()
def list_users():
    """
    List all users. Requires superuser privileges.
    ---
    tags:
      - Users
    security:
      - BearerAuth: []
    parameters:
      - in: query
        name: page
        schema:
          type: integer
          default: 1
      - in: query
        name: per_page
        schema:
          type: integer
          default: 20
    responses:
      200:
        description: Paginated user list
      403:
        description: Forbidden
    """
    try:
        _require_superuser()
    except AuthError as exc:
        return error_response(exc.message, exc.status_code)

    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(100, max(1, request.args.get("per_page", 20, type=int)))

    users, total = UserService.list_users(page=page, per_page=per_page)
    return paginated_response(
        items=[u.to_dict() for u in users],
        total=total,
        page=page,
        per_page=per_page,
    )


@users_bp.get("/<user_id>")
@jwt_required()
def get_user(user_id: str):
    """
    Get a user by ID. Requires superuser privileges.
    ---
    tags:
      - Users
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: user_id
        required: true
        schema:
          type: string
    responses:
      200:
        description: User found
      403:
        description: Forbidden
      404:
        description: Not found
    """
    try:
        _require_superuser()
        user = UserService.get_user(user_id)
        return success_response(data=user.to_dict(include_sensitive=True))
    except AuthError as exc:
        return error_response(exc.message, exc.status_code)
