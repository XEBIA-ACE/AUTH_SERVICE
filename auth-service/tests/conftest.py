"""
Pytest shared fixtures.

All fixtures here are available in every test module automatically.
"""
import pytest

from app import create_app
from app.extensions import db as _db
from app.models.user import User
from app.utils.security import hash_password


@pytest.fixture(scope="session")
def app():
    """Create a testing Flask application (SQLite in-memory)."""
    application = create_app("testing")
    with application.app_context():
        _db.create_all()
        yield application
        _db.drop_all()


@pytest.fixture(scope="function")
def db(app):
    """
    Provide a clean database session for each test.

    Wraps each test in a transaction that is rolled back at the end,
    keeping tests fully isolated without recreating the schema.
    """
    with app.app_context():
        connection = _db.engine.connect()
        transaction = connection.begin()
        _db.session.bind = connection

        yield _db

        _db.session.remove()
        transaction.rollback()
        connection.close()


@pytest.fixture(scope="function")
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture(scope="function")
def runner(app):
    """Flask CLI test runner."""
    return app.test_cli_runner()


# ---------------------------------------------------------------------------
# User factory fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def regular_user(db):
    """Create and persist a standard user for testing."""
    user = User(
        email="testuser@example.com",
        username="testuser",
        password_hash=hash_password("SecureP@ss1"),
        first_name="Test",
        last_name="User",
        is_active=True,
        is_verified=True,
    )
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture(scope="function")
def superuser(db):
    """Create and persist a superuser for testing admin endpoints."""
    user = User(
        email="admin@example.com",
        username="admin",
        password_hash=hash_password("AdminP@ss1"),
        is_active=True,
        is_verified=True,
        is_superuser=True,
    )
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture(scope="function")
def auth_headers(client, regular_user):
    """Return JWT Authorization headers for the regular_user."""
    response = client.post(
        "/api/v1/auth/login",
        json={"identifier": regular_user.email, "password": "SecureP@ss1"},
    )
    data = response.get_json()
    token = data["data"]["tokens"]["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="function")
def admin_headers(client, superuser):
    """Return JWT Authorization headers for the superuser."""
    response = client.post(
        "/api/v1/auth/login",
        json={"identifier": superuser.email, "password": "AdminP@ss1"},
    )
    data = response.get_json()
    token = data["data"]["tokens"]["access_token"]
    return {"Authorization": f"Bearer {token}"}
