"""
Input validation helpers.

Centralizes all validation logic so that it can be reused across
request schemas and service layer checks.
"""
import re
from typing import Optional

# RFC 5322 compliant email pattern (simplified)
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

# Usernames: 3-30 chars, letters/digits/underscores/hyphens, must start with letter
_USERNAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_\-]{2,29}$")

# URL pattern (basic, http/https only)
_URL_RE = re.compile(
    r"^https?://"
    r"(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}"
    r"(?::\d{2,5})?"
    r"(?:/[^\s]*)?$"
)


class ValidationError(Exception):
    """Raised when input validation fails."""

    def __init__(self, message: str, field: Optional[str] = None):
        self.message = message
        self.field = field
        super().__init__(message)

    def to_dict(self) -> dict:
        d = {"message": self.message}
        if self.field:
            d["field"] = self.field
        return d


def validate_email(email: str) -> str:
    """Validate and normalize an email address."""
    if not email or not isinstance(email, str):
        raise ValidationError("Email is required", field="email")
    email = email.strip().lower()
    if len(email) > 255:
        raise ValidationError("Email must be 255 characters or fewer", field="email")
    if not _EMAIL_RE.match(email):
        raise ValidationError("Invalid email address format", field="email")
    return email


def validate_username(username: str) -> str:
    """Validate and normalize a username."""
    if not username or not isinstance(username, str):
        raise ValidationError("Username is required", field="username")
    username = username.strip()
    if not _USERNAME_RE.match(username):
        raise ValidationError(
            "Username must be 3–30 characters, start with a letter, "
            "and contain only letters, digits, underscores, or hyphens.",
            field="username",
        )
    return username


def validate_password(password: str, min_length: int = 8, max_length: int = 128) -> str:
    """Validate password strength."""
    if not password or not isinstance(password, str):
        raise ValidationError("Password is required", field="password")
    if len(password) < min_length:
        raise ValidationError(
            f"Password must be at least {min_length} characters", field="password"
        )
    if len(password) > max_length:
        raise ValidationError(
            f"Password must be {max_length} characters or fewer", field="password"
        )
    # Enforce at least one uppercase, one lowercase, one digit
    checks = [
        (re.search(r"[A-Z]", password), "at least one uppercase letter"),
        (re.search(r"[a-z]", password), "at least one lowercase letter"),
        (re.search(r"\d", password), "at least one digit"),
    ]
    failed = [msg for check, msg in checks if not check]
    if failed:
        raise ValidationError(
            f"Password must contain {', '.join(failed)}", field="password"
        )
    return password


def validate_url(url: str, field: str = "url") -> str:
    """Validate an HTTP/HTTPS URL."""
    if not url or not isinstance(url, str):
        raise ValidationError(f"{field} is required", field=field)
    url = url.strip()
    if not _URL_RE.match(url):
        raise ValidationError(f"'{url}' is not a valid URL", field=field)
    return url


def validate_redirect_uri(uri: str) -> str:
    """Validate an OAuth redirect URI. Localhost allowed for dev."""
    if not uri:
        raise ValidationError("redirect_uri is required", field="redirect_uri")
    uri = uri.strip()
    # Allow http://localhost/* for development
    if re.match(r"^http://localhost(?::\d+)?(/.*)?$", uri):
        return uri
    if re.match(r"^http://127\.0\.0\.1(?::\d+)?(/.*)?$", uri):
        return uri
    return validate_url(uri, field="redirect_uri")


def validate_scope(requested: str, allowed: list[str]) -> str:
    """
    Validate that all requested OAuth scopes are within the allowed set.

    Args:
        requested: Space-separated scope string from the request.
        allowed: List of scopes the client is permitted to request.

    Returns:
        The validated, normalized scope string.

    Raises:
        ValidationError: If any requested scope is not in the allowed list.
    """
    if not requested:
        return ""
    requested_scopes = requested.strip().split()
    invalid = set(requested_scopes) - set(allowed)
    if invalid:
        raise ValidationError(
            f"Requested scopes are not allowed: {', '.join(sorted(invalid))}",
            field="scope",
        )
    return " ".join(requested_scopes)
