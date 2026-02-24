"""
Standardized API response helpers.

All API endpoints must return JSON via these helpers to maintain
a consistent envelope format:

  Success: {"success": true, "data": {...}, "message": "..."}
  Error:   {"success": false, "error": "...", "details": {...}}
"""
from typing import Any, Optional
from flask import jsonify


def success_response(
    data: Any = None,
    message: str = "OK",
    status_code: int = 200,
    meta: Optional[dict] = None,
) -> tuple:
    """
    Build a standardized success JSON response.

    Args:
        data: The payload to return (dict, list, or scalar).
        message: Human-readable success message.
        status_code: HTTP status code (2xx).
        meta: Optional metadata (pagination, rate-limit info, etc.).

    Returns:
        (flask.Response, int) tuple suitable for returning from a view.
    """
    body: dict = {"success": True, "message": message}
    if data is not None:
        body["data"] = data
    if meta is not None:
        body["meta"] = meta
    return jsonify(body), status_code


def error_response(
    message: str,
    status_code: int = 400,
    details: Optional[dict] = None,
) -> tuple:
    """
    Build a standardized error JSON response.

    Args:
        message: Human-readable error message.
        status_code: HTTP status code (4xx or 5xx).
        details: Optional structured error details (field-level validation errors, etc.).

    Returns:
        (flask.Response, int) tuple suitable for returning from a view.
    """
    body: dict = {"success": False, "error": message}
    if details:
        body["details"] = details
    return jsonify(body), status_code


def paginated_response(
    items: list,
    total: int,
    page: int,
    per_page: int,
    message: str = "OK",
) -> tuple:
    """
    Build a paginated success response with navigation metadata.

    Args:
        items: The current page of serialized items.
        total: Total number of items across all pages.
        page: Current 1-based page number.
        per_page: Number of items per page.
        message: Human-readable success message.

    Returns:
        (flask.Response, int) tuple suitable for returning from a view.
    """
    import math
    meta = {
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": math.ceil(total / per_page) if per_page > 0 else 0,
    }
    return success_response(data=items, message=message, meta=meta)
