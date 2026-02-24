"""Unit tests for input validators."""
import pytest
from app.utils.validators import (
    validate_email,
    validate_username,
    validate_password,
    validate_url,
    ValidationError,
)


class TestEmailValidator:
    def test_valid_email(self):
        assert validate_email("user@example.com") == "user@example.com"

    def test_email_normalized_to_lowercase(self):
        assert validate_email("USER@EXAMPLE.COM") == "user@example.com"

    def test_email_strips_whitespace(self):
        assert validate_email("  user@example.com  ") == "user@example.com"

    def test_invalid_email_no_at(self):
        with pytest.raises(ValidationError, match="Invalid email"):
            validate_email("notanemail")

    def test_invalid_email_no_domain(self):
        with pytest.raises(ValidationError):
            validate_email("user@")

    def test_empty_email(self):
        with pytest.raises(ValidationError, match="required"):
            validate_email("")

    def test_email_too_long(self):
        long_email = "a" * 250 + "@example.com"
        with pytest.raises(ValidationError, match="255"):
            validate_email(long_email)


class TestUsernameValidator:
    def test_valid_username(self):
        assert validate_username("alice123") == "alice123"

    def test_username_strips_whitespace(self):
        assert validate_username("  alice  ") == "alice"

    def test_username_too_short(self):
        with pytest.raises(ValidationError):
            validate_username("ab")

    def test_username_must_start_with_letter(self):
        with pytest.raises(ValidationError):
            validate_username("1user")

    def test_username_allows_underscores_and_hyphens(self):
        assert validate_username("alice_smith") == "alice_smith"
        assert validate_username("alice-smith") == "alice-smith"

    def test_username_rejects_spaces(self):
        with pytest.raises(ValidationError):
            validate_username("alice smith")


class TestPasswordValidator:
    def test_valid_password(self):
        assert validate_password("SecureP@ss1") == "SecureP@ss1"

    def test_password_too_short(self):
        with pytest.raises(ValidationError, match="at least"):
            validate_password("Short1", min_length=8)

    def test_password_no_uppercase(self):
        with pytest.raises(ValidationError, match="uppercase"):
            validate_password("lowercase1")

    def test_password_no_lowercase(self):
        with pytest.raises(ValidationError, match="lowercase"):
            validate_password("UPPERCASE1")

    def test_password_no_digit(self):
        with pytest.raises(ValidationError, match="digit"):
            validate_password("NoDigitsHere")

    def test_password_too_long(self):
        with pytest.raises(ValidationError, match="128"):
            validate_password("A1" + "a" * 200, max_length=128)


class TestUrlValidator:
    def test_valid_https_url(self):
        assert validate_url("https://example.com/callback") == "https://example.com/callback"

    def test_valid_http_url(self):
        assert validate_url("http://example.com") == "http://example.com"

    def test_invalid_url(self):
        with pytest.raises(ValidationError):
            validate_url("not-a-url")

    def test_ftp_url_rejected(self):
        with pytest.raises(ValidationError):
            validate_url("ftp://example.com")
