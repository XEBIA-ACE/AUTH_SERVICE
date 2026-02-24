"""
Health & Metrics Endpoints

GET /api/v1/health      — Liveness probe (always 200 if the process is up)
GET /api/v1/health/ready — Readiness probe (checks DB + Redis connectivity)
GET /api/v1/metrics     — Basic operational counters (extend with Prometheus if needed)
"""
import time
import logging
from datetime import datetime, timezone

from flask import Blueprint, current_app, jsonify

from app.extensions import db
from app.utils.response import success_response, error_response

health_bp = Blueprint("health", __name__)
logger = logging.getLogger(__name__)

# Record start time for uptime calculation
_START_TIME = time.time()


@health_bp.get("/health")
def liveness():
    """
    Liveness probe — returns 200 as long as the process is running.
    ---
    tags:
      - Health
    responses:
      200:
        description: Service is alive
    """
    return success_response(
        data={
            "status": "ok",
            "service": current_app.config.get("APP_NAME", "auth-service"),
            "version": current_app.config.get("API_VERSION", "v1"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "uptime_seconds": round(time.time() - _START_TIME, 2),
        },
        message="Service is healthy",
    )


@health_bp.get("/health/ready")
def readiness():
    """
    Readiness probe — checks connectivity to all required backing services.
    Returns 503 if any dependency is unavailable.
    ---
    tags:
      - Health
    responses:
      200:
        description: Service is ready to accept traffic
      503:
        description: One or more dependencies are unavailable
    """
    checks = {}
    all_ok = True

    # Database check
    try:
        db.session.execute(db.text("SELECT 1"))
        checks["database"] = {"status": "ok"}
    except Exception as exc:
        logger.error("Database health check failed: %s", exc)
        checks["database"] = {"status": "error", "detail": str(exc)}
        all_ok = False

    # Redis check
    try:
        import redis
        r = redis.from_url(
            current_app.config.get("REDIS_URL", "redis://localhost:6379/0"),
            socket_connect_timeout=2,
        )
        r.ping()
        checks["redis"] = {"status": "ok"}
    except Exception as exc:
        logger.error("Redis health check failed: %s", exc)
        checks["redis"] = {"status": "error", "detail": str(exc)}
        all_ok = False

    status_code = 200 if all_ok else 503
    return (
        jsonify(
            {
                "success": all_ok,
                "status": "ready" if all_ok else "not_ready",
                "checks": checks,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ),
        status_code,
    )


@health_bp.get("/metrics")
def metrics():
    """
    Basic operational metrics.
    For production, expose a /metrics endpoint in Prometheus format via prometheus-flask-exporter.
    ---
    tags:
      - Health
    responses:
      200:
        description: Basic service metrics
    """
    try:
        from app.models.user import User
        from app.models.oauth_token import OAuthToken

        user_count = db.session.query(db.func.count(User.id)).scalar()
        active_user_count = db.session.query(
            db.func.count(User.id)
        ).filter_by(is_active=True).scalar()
        active_token_count = db.session.query(
            db.func.count(OAuthToken.id)
        ).filter_by(is_revoked=False).scalar()

        return success_response(
            data={
                "uptime_seconds": round(time.time() - _START_TIME, 2),
                "users_total": user_count,
                "users_active": active_user_count,
                "oauth_tokens_active": active_token_count,
            }
        )
    except Exception as exc:
        logger.error("Metrics collection error: %s", exc)
        return error_response("Metrics temporarily unavailable", 503)
