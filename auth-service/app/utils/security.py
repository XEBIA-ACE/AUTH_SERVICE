"""
Security utilities: password hashing, PKCE, token generation.
"""
import hashlib
import hmac
import os
import secrets
import base64

import bcrypt


def hash_password(plaintext: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plaintext: str, hashed: str) -> bool:
    """
    Verify a plaintext password against a bcrypt hash.
    Uses a constant-time comparison to prevent timing attacks.
    """
    try:
        return bcrypt.checkpw(plaintext.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def hash_secret(plaintext: str) -> str:
    """Hash an OAuth client secret using bcrypt."""
    return hash_password(plaintext)


def verify_secret(plaintext: str, hashed: str) -> bool:
    """Verify an OAuth client secret."""
    return verify_password(plaintext, hashed)


def generate_token(nbytes: int = 32) -> str:
    """Generate a cryptographically secure URL-safe random token."""
    return secrets.token_urlsafe(nbytes)


def generate_opaque_token() -> str:
    """Generate a 256-bit opaque bearer token string."""
    return secrets.token_hex(32)


# ---------------------------------------------------------------------------
# PKCE (Proof Key for Code Exchange) — RFC 7636
# ---------------------------------------------------------------------------

def generate_pkce_verifier() -> str:
    """Generate a PKCE code verifier (43-128 unreserved URI chars)."""
    return secrets.token_urlsafe(64)[:128]


def compute_pkce_challenge(verifier: str, method: str = "S256") -> str:
    """
    Compute the PKCE code challenge from a verifier.

    Args:
        verifier: The code verifier string (must be 43-128 chars).
        method: "S256" (SHA-256, recommended) or "plain".

    Returns:
        The code challenge string.
    """
    if method == "S256":
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    elif method == "plain":
        return verifier
    else:
        raise ValueError(f"Unsupported PKCE method: {method}")


def verify_pkce_challenge(verifier: str, challenge: str, method: str) -> bool:
    """
    Verify a PKCE code verifier against the stored challenge.

    Args:
        verifier: The verifier provided by the client during token exchange.
        challenge: The challenge stored when the authorization code was issued.
        method: The method used to compute the challenge ("S256" or "plain").

    Returns:
        True if the verifier matches the challenge.
    """
    expected = compute_pkce_challenge(verifier, method)
    # Use hmac.compare_digest for constant-time comparison
    return hmac.compare_digest(expected.encode(), challenge.encode())


def constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing side-channels."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
