"""
Auth Service - Application Factory
"""
from flask import Flask
from app.config import get_config
from app.extensions import db, migrate, jwt, limiter, cors, swagger


def create_app(config_name: str = None) -> Flask:
    """
    Create and configure the Flask application using the Application Factory pattern.

    Args:
        config_name: Configuration environment name ('development', 'testing', 'production').
                     Defaults to the FLASK_ENV environment variable or 'development'.

    Returns:
        Configured Flask application instance.
    """
    app = Flask(__name__)

    # Load configuration
    config = get_config(config_name)
    app.config.from_object(config)

    # Initialize extensions
    _init_extensions(app)

    # Register blueprints
    _register_blueprints(app)

    # Register error handlers
    _register_error_handlers(app)

    # Configure structured logging
    _configure_logging(app)

    return app


def _init_extensions(app: Flask) -> None:
    """Initialize all Flask extensions."""
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    limiter.init_app(app)
    cors.init_app(app, resources={r"/api/*": {"origins": app.config.get("CORS_ORIGINS", "*")}})
    swagger.init_app(app)


def _register_blueprints(app: Flask) -> None:
    """Register all API blueprints."""
    from app.api.auth import auth_bp
    from app.api.users import users_bp
    from app.api.oauth import oauth_bp
    from app.api.health import health_bp

    app.register_blueprint(health_bp, url_prefix="/api/v1")
    app.register_blueprint(auth_bp, url_prefix="/api/v1/auth")
    app.register_blueprint(users_bp, url_prefix="/api/v1/users")
    app.register_blueprint(oauth_bp, url_prefix="/api/v1/oauth")


def _register_error_handlers(app: Flask) -> None:
    """Register global error handlers."""
    from app.utils.response import error_response
    from flask_jwt_extended.exceptions import JWTExtendedException
    from werkzeug.exceptions import HTTPException
    import logging

    logger = logging.getLogger(__name__)

    @app.errorhandler(400)
    def bad_request(e):
        return error_response(str(e.description), 400)

    @app.errorhandler(401)
    def unauthorized(e):
        return error_response("Authentication required", 401)

    @app.errorhandler(403)
    def forbidden(e):
        return error_response("Insufficient permissions", 403)

    @app.errorhandler(404)
    def not_found(e):
        return error_response("Resource not found", 404)

    @app.errorhandler(405)
    def method_not_allowed(e):
        return error_response("Method not allowed", 405)

    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return error_response("Rate limit exceeded. Please try again later.", 429)

    @app.errorhandler(JWTExtendedException)
    def handle_jwt_error(e):
        return error_response(str(e), 401)

    @app.errorhandler(Exception)
    def handle_unexpected_error(e):
        if isinstance(e, HTTPException):
            return error_response(e.description, e.code)
        logger.exception("Unexpected error: %s", str(e))
        return error_response("An unexpected error occurred", 500)


def _configure_logging(app: Flask) -> None:
    """Configure structured JSON logging."""
    import logging
    import json
    import sys

    class JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            log_data = {
                "timestamp": self.formatTime(record),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "module": record.module,
                "function": record.funcName,
                "line": record.lineno,
            }
            if record.exc_info:
                log_data["exception"] = self.formatException(record.exc_info)
            return json.dumps(log_data)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())

    log_level = app.config.get("LOG_LEVEL", "INFO")
    logging.basicConfig(level=getattr(logging, log_level), handlers=[handler])

    # Suppress noisy loggers in production
    if not app.debug:
        logging.getLogger("werkzeug").setLevel(logging.WARNING)
