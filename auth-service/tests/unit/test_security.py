"""Unit tests for security utilities."""
import pytest
from app.utils.security import (
    hash_password,
    verify_password,
    generate_token,
    generate_pkce_verifier,
    compute_pkce_challenge,
    verify_pkce_challenge,
)


class TestPasswordHashing:
    def test_hash_produces_different_value(self):
        plaintext = "SecureP@ss1"
        hashed = hash_password(plaintext)
        assert hashed != plaintext

    def test_verify_correct_password(self):
        plaintext = "SecureP@ss1"
        hashed = hash_password(plaintext)
        assert verify_password(plaintext, hashed) is True

    def test_verify_wrong_password(self):
        hashed = hash_password("SecureP@ss1")
        assert verify_password("WrongPassword1", hashed) is False

    def test_same_password_different_hashes(self):
        """bcrypt uses a unique salt each time."""
        pw = "SecureP@ss1"
        assert hash_password(pw) != hash_password(pw)

    def test_empty_string_does_not_verify_against_hash(self):
        hashed = hash_password("SecureP@ss1")
        assert verify_password("", hashed) is False


class TestTokenGeneration:
    def test_generate_token_length(self):
        token = generate_token(32)
        assert len(token) > 0

    def test_generate_token_unique(self):
        tokens = {generate_token() for _ in range(100)}
        assert len(tokens) == 100

    def test_generate_pkce_verifier_length(self):
        verifier = generate_pkce_verifier()
        assert 43 <= len(verifier) <= 128


class TestPKCE:
    def test_s256_challenge_round_trip(self):
        verifier = generate_pkce_verifier()
        challenge = compute_pkce_challenge(verifier, "S256")
        assert verify_pkce_challenge(verifier, challenge, "S256") is True

    def test_plain_challenge_round_trip(self):
        verifier = generate_pkce_verifier()
        challenge = compute_pkce_challenge(verifier, "plain")
        assert verify_pkce_challenge(verifier, challenge, "plain") is True

    def test_wrong_verifier_fails(self):
        verifier = generate_pkce_verifier()
        challenge = compute_pkce_challenge(verifier, "S256")
        wrong_verifier = generate_pkce_verifier()
        assert verify_pkce_challenge(wrong_verifier, challenge, "S256") is False

    def test_unsupported_method_raises(self):
        with pytest.raises(ValueError, match="Unsupported"):
            compute_pkce_challenge("verifier", "md5")
