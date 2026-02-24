"""
Application Configuration

Supports multiple environments: development, testing, production.
All sensitive values are read from environment variables.
"""
import os
from datetime import timedelta
from typing import Type


class BaseConfig:
    """Base configuration shared across all environments."""

    # Flask
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "change-me-in-production")
    DEBUG: bool = False
    TESTING: bool = False

    # Database
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "DATABASE_URL", "postgresql://auth_user:auth_pass@localhost:5432/auth_db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ECHO: bool = False
    SQLALCHEMY_ENGINE_OPTIONS: dict = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
        "pool_size": 10,
        "max_overflow": 20,
    }

    # Redis
    REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

    # JWT Configuration
    JWT_SECRET_KEY: str = os.environ.get("JWT_SECRET_KEY", "jwt-secret-change-me")
    JWT_ACCESS_TOKEN_EXPIRES: timedelta = timedelta(
        minutes=int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRES_MINUTES", "15"))
    )
    JWT_REFRESH_TOKEN_EXPIRES: timedelta = timedelta(
        days=int(os.environ.get("JWT_REFRESH_TOKEN_EXPIRES_DAYS", "30"))
    )
    JWT_ALGORITHM: str = "HS256"
    JWT_TOKEN_LOCATION: list = ["headers"]
    JWT_HEADER_NAME: str = "Authorization"
    JWT_HEADER_TYPE: str = "Bearer"
    JWT_BLACKLIST_ENABLED: bool = True
    JWT_BLACKLIST_TOKEN_CHECKS: list = ["access", "refresh"]

    # OAuth 2.0
    OAUTH_AUTHORIZATION_CODE_EXPIRES: int = int(
        os.environ.get("OAUTH_AUTHORIZATION_CODE_EXPIRES", "600")  # 10 minutes
    )
    OAUTH_ACCESS_TOKEN_EXPIRES: int = int(
        os.environ.get("OAUTH_ACCESS_TOKEN_EXPIRES", "3600")  # 1 hour
    )
    OAUTH_REFRESH_TOKEN_EXPIRES: int = int(
        os.environ.get("OAUTH_REFRESH_TOKEN_EXPIRES", "2592000")  # 30 days
    )

    # Rate Limiting
    RATELIMIT_DEFAULT: str = os.environ.get("RATELIMIT_DEFAULT", "200 per day;50 per hour")
    RATELIMIT_STORAGE_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    RATELIMIT_STRATEGY: str = "fixed-window"
    RATELIMIT_HEADERS_ENABLED: bool = True

    # CORS
    CORS_ORIGINS: list = os.environ.get("CORS_ORIGINS", "*").split(",")

    # Security
    BCRYPT_LOG_ROUNDS: int = int(os.environ.get("BCRYPT_LOG_ROUNDS", "12"))
    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_MAX_LENGTH: int = 128

    # Email (for verification flows)
    MAIL_SERVER: str = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT: int = int(os.environ.get("MAIL_PORT", "587"))
    MAIL_USE_TLS: bool = True
    MAIL_USERNAME: str = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD: str = os.environ.get("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER: str = os.environ.get("MAIL_DEFAULT_SENDER", "noreply@authservice.local")

    # Swagger / OpenAPI
    SWAGGER: dict = {
        "title": "Authentication Service API",
        "uiversion": 3,
        "openapi": "3.0.3",
        "description": "Production-ready OAuth 2.0 Authentication Service",
        "version": "1.0.0",
        "termsOfService": "",
        "contact": {"email": "support@authservice.local"},
        "license": {"name": "MIT"},
        "specs_route": "/api/docs/",
    }

    # Logging
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")

    # Application
    APP_NAME: str = "auth-service"
    API_VERSION: str = "v1"


class DevelopmentConfig(BaseConfig):
    """Development-specific configuration."""

    DEBUG: bool = True
    LOG_LEVEL: str = "DEBUG"
    SQLALCHEMY_ECHO: bool = False  # Set True to see SQL queries
    BCRYPT_LOG_ROUNDS: int = 4   # Faster hashing during development
    RATELIMIT_DEFAULT: str = "10000 per day;1000 per hour"


class TestingConfig(BaseConfig):
    """Testing-specific configuration."""

    TESTING: bool = True
    DEBUG: bool = True
    SQLALCHEMY_DATABASE_URI: str = os.environ.get(
        "TEST_DATABASE_URL", "sqlite:///:memory:"
    )
    BCRYPT_LOG_ROUNDS: int = 4
    JWT_ACCESS_TOKEN_EXPIRES: timedelta = timedelta(minutes=5)
    JWT_REFRESH_TOKEN_EXPIRES: timedelta = timedelta(minutes=10)
    RATELIMIT_ENABLED: bool = False
    WTF_CSRF_ENABLED: bool = False


class ProductionConfig(BaseConfig):
    """Production-specific configuration with strict security defaults."""

    DEBUG: bool = False
    SQLALCHEMY_ECHO: bool = False
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "WARNING")

    @classmethod
    def validate(cls) -> None:
        """Validate that all required production secrets are set."""
        required = ["SECRET_KEY", "JWT_SECRET_KEY", "DATABASE_URL"]
        missing = [key for key in required if not os.environ.get(key)]
        if missing:
            raise EnvironmentError(
                f"Missing required environment variables for production: {missing}"
            )


CONFIG_MAP: dict[str, Type[BaseConfig]] = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config(config_name: str = None) -> Type[BaseConfig]:
    """
    Return the configuration class for the given environment name.

    Args:
        config_name: One of 'development', 'testing', 'production'.
                     Falls back to FLASK_ENV env var, then 'development'.
    """
    env = config_name or os.environ.get("FLASK_ENV", "development")
    config = CONFIG_MAP.get(env, DevelopmentConfig)
    if env == "production" and hasattr(config, "validate"):
        config.validate()
    return config
