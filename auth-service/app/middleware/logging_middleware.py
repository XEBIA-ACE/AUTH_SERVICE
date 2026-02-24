"""
Request/Response Logging Middleware

Logs every inbound request and outbound response with structured JSON
so that log aggregators (Datadog, CloudWatch, ELK) can parse fields directly.

Usage — register before any blueprint in the app factory:
    from app.middleware.logging_middleware import register_request_logging
    register_request_logging(app)
"""
import json
import logging
import time
import uuid

from flask import Flask, g, request

logger = logging.getLogger("auth_service.access")


def register_request_logging(app: Flask) -> None:
    """Attach before/after request hooks for structured access logging."""

    @app.before_request
    def before_request():
        # Assign a unique request ID for correlation across log lines
        g.request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        g.start_time = time.time()

    @app.after_request
    def after_request(response):
        duration_ms = round((time.time() - g.get("start_time", time.time())) * 1000, 2)
        request_id = g.get("request_id", "-")

        log_record = {
            "request_id": request_id,
            "method": request.method,
            "path": request.path,
            "query": request.query_string.decode("utf-8"),
            "status": response.status_code,
            "duration_ms": duration_ms,
            "remote_addr": request.remote_addr,
            "user_agent": request.user_agent.string,
            "content_length": response.content_length,
        }

        if response.status_code >= 500:
            logger.error(json.dumps(log_record))
        elif response.status_code >= 400:
            logger.warning(json.dumps(log_record))
        else:
            logger.info(json.dumps(log_record))

        # Echo the request ID back in the response for client-side correlation
        response.headers["X-Request-ID"] = request_id
        return response
