"""
Flask Extension Instances

Extensions are initialized here and bound to the app in the factory (app/__init__.py).
This module-level pattern avoids circular imports.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flasgger import Swagger

# SQLAlchemy ORM
db = SQLAlchemy()

# Alembic database migrations
migrate = Migrate()

# JWT token management
jwt = JWTManager()

# Rate limiting (backed by Redis in production)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)

# Cross-Origin Resource Sharing
cors = CORS()

# OpenAPI / Swagger UI
swagger = Swagger()


# ---------------------------------------------------------------------------
# JWT callback hooks
# ---------------------------------------------------------------------------

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    """
    Check whether a JWT has been revoked (added to Redis blocklist on logout).
    Returns True if the token is blocklisted and should be rejected.
    """
    from app.services.token_service import TokenService
    jti = jwt_payload.get("jti")
    return TokenService.is_token_revoked(jti)


@jwt.user_identity_loader
def user_identity_lookup(user):
    """Serialize the user identity into the JWT subject claim."""
    if hasattr(user, "id"):
        return str(user.id)
    return str(user)


@jwt.user_lookup_loader
def user_lookup_callback(jwt_header, jwt_data):
    """
    Deserialize the JWT subject back into a User object.
    Called automatically when @jwt_required(optional=False) is used.
    """
    from app.repositories.user_repository import UserRepository
    identity = jwt_data["sub"]
    return UserRepository.get_by_id(identity)


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    from app.utils.response import error_response
    return error_response("Token has expired", 401, {"token_status": "expired"})


@jwt.invalid_token_loader
def invalid_token_callback(error):
    from app.utils.response import error_response
    return error_response("Invalid token", 401, {"token_status": "invalid"})


@jwt.unauthorized_loader
def missing_token_callback(error):
    from app.utils.response import error_response
    return error_response("Authorization token is missing", 401, {"token_status": "missing"})


@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    from app.utils.response import error_response
    return error_response("Token has been revoked", 401, {"token_status": "revoked"})
