"""Integration tests for the authentication API endpoints."""
import pytest


class TestRegister:
    def test_register_success(self, client, db):
        resp = client.post(
            "/api/v1/auth/register",
            json={
                "email": "new@example.com",
                "username": "newuser",
                "password": "SecureP@ss1",
                "first_name": "New",
                "last_name": "User",
            },
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["success"] is True
        assert data["data"]["email"] == "new@example.com"
        assert "password_hash" not in data["data"]

    def test_register_duplicate_email(self, client, db, regular_user):
        resp = client.post(
            "/api/v1/auth/register",
            json={
                "email": regular_user.email,
                "username": "uniqueuser",
                "password": "SecureP@ss1",
            },
        )
        assert resp.status_code == 409

    def test_register_duplicate_username(self, client, db, regular_user):
        resp = client.post(
            "/api/v1/auth/register",
            json={
                "email": "unique@example.com",
                "username": regular_user.username,
                "password": "SecureP@ss1",
            },
        )
        assert resp.status_code == 409

    def test_register_invalid_email(self, client, db):
        resp = client.post(
            "/api/v1/auth/register",
            json={"email": "bad-email", "username": "someone", "password": "SecureP@ss1"},
        )
        assert resp.status_code == 400

    def test_register_weak_password(self, client, db):
        resp = client.post(
            "/api/v1/auth/register",
            json={"email": "pw@example.com", "username": "pwuser", "password": "weak"},
        )
        assert resp.status_code == 400

    def test_register_missing_fields(self, client, db):
        resp = client.post("/api/v1/auth/register", json={})
        assert resp.status_code == 400


class TestLogin:
    def test_login_with_email(self, client, db, regular_user):
        resp = client.post(
            "/api/v1/auth/login",
            json={"identifier": regular_user.email, "password": "SecureP@ss1"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "access_token" in data["data"]["tokens"]
        assert "refresh_token" in data["data"]["tokens"]

    def test_login_with_username(self, client, db, regular_user):
        resp = client.post(
            "/api/v1/auth/login",
            json={"identifier": regular_user.username, "password": "SecureP@ss1"},
        )
        assert resp.status_code == 200

    def test_login_wrong_password(self, client, db, regular_user):
        resp = client.post(
            "/api/v1/auth/login",
            json={"identifier": regular_user.email, "password": "WrongPass1"},
        )
        assert resp.status_code == 401

    def test_login_unknown_user(self, client, db):
        resp = client.post(
            "/api/v1/auth/login",
            json={"identifier": "nobody@example.com", "password": "Whatever1"},
        )
        assert resp.status_code == 401

    def test_login_inactive_user(self, client, db, regular_user):
        regular_user.is_active = False
        db.session.commit()
        resp = client.post(
            "/api/v1/auth/login",
            json={"identifier": regular_user.email, "password": "SecureP@ss1"},
        )
        assert resp.status_code == 403


class TestLogout:
    def test_logout_success(self, client, db, auth_headers):
        resp = client.post("/api/v1/auth/logout", headers=auth_headers)
        assert resp.status_code == 200

    def test_logout_without_token(self, client, db):
        resp = client.post("/api/v1/auth/logout")
        assert resp.status_code == 401

    def test_token_revoked_after_logout(self, client, db, auth_headers):
        client.post("/api/v1/auth/logout", headers=auth_headers)
        # Using the same token again should fail
        resp = client.get("/api/v1/users/me", headers=auth_headers)
        assert resp.status_code == 401


class TestTokenRefresh:
    def test_refresh_success(self, client, db, regular_user):
        login_resp = client.post(
            "/api/v1/auth/login",
            json={"identifier": regular_user.email, "password": "SecureP@ss1"},
        )
        refresh_token = login_resp.get_json()["data"]["tokens"]["refresh_token"]
        resp = client.post(
            "/api/v1/auth/refresh",
            headers={"Authorization": f"Bearer {refresh_token}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "access_token" in data["data"]

    def test_refresh_with_access_token_fails(self, client, db, auth_headers):
        # Access tokens cannot be used at the refresh endpoint
        resp = client.post("/api/v1/auth/refresh", headers=auth_headers)
        assert resp.status_code == 422  # JWT extended raises 422 for wrong token type


class TestEmailVerification:
    def test_verify_valid_token(self, client, db, regular_user):
        import secrets
        token = secrets.token_urlsafe(32)
        regular_user.is_verified = False
        regular_user.email_verification_token = token
        db.session.commit()

        resp = client.post("/api/v1/auth/verify-email", json={"token": token})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["data"]["is_verified"] is True

    def test_verify_invalid_token(self, client, db):
        resp = client.post("/api/v1/auth/verify-email", json={"token": "badtoken"})
        assert resp.status_code == 400

    def test_verify_missing_token(self, client, db):
        resp = client.post("/api/v1/auth/verify-email", json={})
        assert resp.status_code == 400


class TestPasswordReset:
    def test_forgot_password_always_200(self, client, db):
        # Should not reveal whether the email exists
        resp = client.post(
            "/api/v1/auth/forgot-password",
            json={"email": "notreal@example.com"},
        )
        assert resp.status_code == 200

    def test_reset_password_valid(self, client, db, regular_user):
        import secrets
        from datetime import datetime, timezone, timedelta

        token = secrets.token_urlsafe(32)
        regular_user.password_reset_token = token
        regular_user.password_reset_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        db.session.commit()

        resp = client.post(
            "/api/v1/auth/reset-password",
            json={"token": token, "new_password": "NewSecureP@ss1"},
        )
        assert resp.status_code == 200

    def test_reset_password_expired_token(self, client, db, regular_user):
        import secrets
        from datetime import datetime, timezone, timedelta

        token = secrets.token_urlsafe(32)
        regular_user.password_reset_token = token
        regular_user.password_reset_expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        db.session.commit()

        resp = client.post(
            "/api/v1/auth/reset-password",
            json={"token": token, "new_password": "NewSecureP@ss1"},
        )
        assert resp.status_code == 400
