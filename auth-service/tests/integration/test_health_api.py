"""Integration tests for health and metrics endpoints."""


class TestLiveness:
    def test_liveness_200(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["data"]["status"] == "ok"
        assert "uptime_seconds" in data["data"]

    def test_liveness_has_service_name(self, client):
        resp = client.get("/api/v1/health")
        assert "service" in resp.get_json()["data"]


class TestReadiness:
    def test_readiness_db_check_present(self, client):
        resp = client.get("/api/v1/health/ready")
        data = resp.get_json()
        # DB check should always be present
        assert "database" in data["checks"]


class TestUsers:
    def test_get_me_authenticated(self, client, auth_headers):
        resp = client.get("/api/v1/users/me", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert "email" in data["data"]

    def test_get_me_unauthenticated(self, client):
        resp = client.get("/api/v1/users/me")
        assert resp.status_code == 401

    def test_update_profile(self, client, auth_headers):
        resp = client.put(
            "/api/v1/users/me",
            json={"first_name": "Updated"},
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.get_json()["data"]["first_name"] == "Updated"

    def test_list_users_requires_superuser(self, client, auth_headers):
        resp = client.get("/api/v1/users", headers=auth_headers)
        assert resp.status_code == 403

    def test_list_users_as_superuser(self, client, admin_headers):
        resp = client.get("/api/v1/users", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data["data"], list)
        assert "meta" in data
