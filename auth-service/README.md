# Auth Service

A production-ready OAuth 2.0 Authentication Service built with Python, Flask, and PostgreSQL.

## Features

- **JWT Authentication** — access/refresh token pair with Redis-backed blocklist (instant revocation)
- **OAuth 2.0** — Authorization Code (with PKCE), Client Credentials, and Refresh Token flows
- **Token Introspection** (RFC 7662) and **Token Revocation** (RFC 7009)
- **Account Security** — bcrypt password hashing, brute-force lockout, email verification, password reset
- **Rate Limiting** — Redis-backed per-endpoint rate limits
- **Structured Logging** — JSON log output for log aggregators
- **Health & Metrics** — `/health`, `/health/ready`, `/metrics` endpoints
- **OpenAPI Docs** — Swagger UI at `/api/docs/`
- **Clean Architecture** — API → Service → Repository → Model layers
- **Docker-ready** — multi-stage Dockerfile + docker-compose for local dev

---

## Quick Start (Docker)

```bash
# 1. Clone and enter the project
git clone <repo-url>
cd auth-service

# 2. Configure environment
cp .env.example .env
# Edit .env — at minimum, change SECRET_KEY and JWT_SECRET_KEY

# 3. Start all services
docker-compose up --build

# 4. Open Swagger UI
open http://localhost:5000/api/docs/
```

---

## Local Development (without Docker)

### Prerequisites

- Python 3.12+
- PostgreSQL 14+
- Redis 7+

### Setup

```bash
# Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dev dependencies
pip install -r requirements-dev.txt

# Configure environment
cp .env.example .env
# Edit DATABASE_URL and REDIS_URL in .env to point to your local instances

# Run database migrations
flask db upgrade

# Start the development server
flask run --debug
```

---

## Project Structure

```
auth-service/
├── app/
│   ├── __init__.py          # Application factory
│   ├── config.py            # Multi-environment configuration
│   ├── extensions.py        # Flask extension instances + JWT hooks
│   ├── api/
│   │   ├── auth.py          # Register, login, logout, refresh, password reset
│   │   ├── users.py         # User profile management
│   │   ├── oauth.py         # OAuth 2.0 endpoints (authorize, token, clients)
│   │   └── health.py        # Health checks and metrics
│   ├── models/
│   │   ├── user.py          # User entity
│   │   ├── oauth_client.py  # OAuth application registration
│   │   ├── oauth_token.py   # Issued access/refresh tokens
│   │   └── oauth_authorization_code.py
│   ├── repositories/
│   │   ├── user_repository.py
│   │   └── oauth_repository.py
│   ├── services/
│   │   ├── auth_service.py   # Core auth business logic
│   │   ├── user_service.py   # Profile management
│   │   ├── oauth_service.py  # OAuth 2.0 flows
│   │   └── token_service.py  # JWT lifecycle + Redis blocklist
│   ├── middleware/
│   │   └── logging_middleware.py  # Structured access logging
│   └── utils/
│       ├── response.py      # Standardized JSON response builders
│       ├── validators.py    # Input validation
│       └── security.py      # bcrypt, PKCE, token generation
├── migrations/              # Alembic schema migrations
├── tests/
│   ├── conftest.py          # Shared pytest fixtures
│   ├── unit/                # Fast, no-DB tests
│   └── integration/         # Tests requiring app context
├── .env.example
├── .gitignore
├── Dockerfile               # Multi-stage production image
├── docker-compose.yml       # Local dev stack
├── pyproject.toml           # Ruff, pytest, coverage config
├── requirements.txt
├── requirements-dev.txt
└── wsgi.py                  # Gunicorn entry point
```

---

## API Reference

All responses follow a consistent envelope:

```json
// Success
{ "success": true, "message": "...", "data": { ... } }

// Error
{ "success": false, "error": "...", "details": { ... } }

// Paginated
{ "success": true, "data": [...], "meta": { "page": 1, "per_page": 20, "total": 100, "pages": 5 } }
```

### Authentication

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| `POST` | `/api/v1/auth/register` | Create account | — |
| `POST` | `/api/v1/auth/login` | Login → JWT pair | — |
| `POST` | `/api/v1/auth/logout` | Revoke access token | Bearer |
| `POST` | `/api/v1/auth/refresh` | Rotate refresh token | Bearer (refresh) |
| `POST` | `/api/v1/auth/verify-email` | Confirm email | — |
| `POST` | `/api/v1/auth/forgot-password` | Request reset link | — |
| `POST` | `/api/v1/auth/reset-password` | Set new password via token | — |

**Register**
```bash
curl -X POST http://localhost:5000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","username":"alice","password":"SecureP@ss1"}'
```

**Login**
```bash
curl -X POST http://localhost:5000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"identifier":"alice@example.com","password":"SecureP@ss1"}'
```

### Users

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| `GET` | `/api/v1/users/me` | Get own profile | Bearer |
| `PUT` | `/api/v1/users/me` | Update own profile | Bearer |
| `POST` | `/api/v1/users/me/change-password` | Change password | Bearer |
| `DELETE` | `/api/v1/users/me` | Deactivate own account | Bearer |
| `GET` | `/api/v1/users` | List all users | Bearer (superuser) |
| `GET` | `/api/v1/users/<id>` | Get user by ID | Bearer (superuser) |

### OAuth 2.0

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| `GET` | `/api/v1/oauth/authorize` | Consent page data | Bearer |
| `POST` | `/api/v1/oauth/authorize` | Grant/deny consent | Bearer |
| `POST` | `/api/v1/oauth/token` | Exchange code/credentials for tokens | — |
| `POST` | `/api/v1/oauth/token/revoke` | Revoke a token (RFC 7009) | — |
| `POST` | `/api/v1/oauth/token/introspect` | Token introspection (RFC 7662) | — |
| `POST` | `/api/v1/oauth/clients` | Register OAuth client | Bearer |
| `GET` | `/api/v1/oauth/clients` | List own clients | Bearer |
| `GET` | `/api/v1/oauth/clients/<id>` | Get client details | Bearer |
| `DELETE` | `/api/v1/oauth/clients/<id>` | Delete client | Bearer |

#### Authorization Code Flow (with PKCE)

```bash
# 1. Generate PKCE verifier + challenge (S256)
VERIFIER=$(openssl rand -base64 64 | tr -d '\n=+/' | cut -c1-64)
CHALLENGE=$(echo -n "$VERIFIER" | sha256sum | xxd -r -p | base64 | tr -d '\n=' | tr '+/' '-_')

# 2. Redirect user to the authorization endpoint
GET /api/v1/oauth/authorize
  ?response_type=code
  &client_id=YOUR_CLIENT_ID
  &redirect_uri=https://yourapp.com/callback
  &scope=read
  &state=random-csrf-token
  &code_challenge=$CHALLENGE
  &code_challenge_method=S256

# 3. User grants consent (POST /api/v1/oauth/authorize with action=allow)
# → Redirected to: https://yourapp.com/callback?code=AUTH_CODE&state=...

# 4. Exchange the code for tokens
curl -X POST http://localhost:5000/api/v1/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "redirect_uri=https://yourapp.com/callback" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "code_verifier=$VERIFIER"
```

#### Client Credentials Flow

```bash
curl -X POST http://localhost:5000/api/v1/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "scope=read"
```

### Health

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Liveness probe |
| `GET` | `/api/v1/health/ready` | Readiness probe (DB + Redis) |
| `GET` | `/api/v1/metrics` | Basic operational metrics |

---

## Running Tests

```bash
# All tests
pytest

# Unit tests only (fast, no DB)
pytest tests/unit/ -m unit

# Integration tests
pytest tests/integration/

# With coverage report
pytest --cov=app --cov-report=term-missing

# HTML coverage report
pytest --cov=app --cov-report=html
open htmlcov/index.html
```

---

## Database Migrations

```bash
# Create a new migration (auto-generated from model changes)
flask db migrate -m "Add new column"

# Review the generated script in migrations/versions/ before applying!

# Apply pending migrations
flask db upgrade

# Rollback one revision
flask db downgrade -1

# Show migration history
flask db history
```

---

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_ENV` | `development` | `development` / `testing` / `production` |
| `SECRET_KEY` | *(required)* | Flask session secret |
| `JWT_SECRET_KEY` | *(required)* | JWT signing key |
| `DATABASE_URL` | *(required)* | PostgreSQL connection string |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `JWT_ACCESS_TOKEN_EXPIRES_MINUTES` | `15` | Access token TTL |
| `JWT_REFRESH_TOKEN_EXPIRES_DAYS` | `30` | Refresh token TTL |
| `OAUTH_ACCESS_TOKEN_EXPIRES` | `3600` | OAuth access token TTL (seconds) |
| `BCRYPT_LOG_ROUNDS` | `12` | bcrypt work factor (lower = faster, less secure) |
| `CORS_ORIGINS` | `*` | Comma-separated allowed CORS origins |
| `LOG_LEVEL` | `INFO` | Python logging level |

---

## Architecture Overview

```
HTTP Request
     │
     ▼
┌──────────────────────────────────────────┐
│            Flask Application             │
│  ┌─────────────────────────────────┐     │
│  │   Middleware (logging, CORS)    │     │
│  └───────────────┬─────────────────┘     │
│                  │                       │
│  ┌───────────────▼─────────────────┐     │
│  │         API Layer (Routes)      │     │
│  │  auth.py │ users.py │ oauth.py  │     │
│  └───────────────┬─────────────────┘     │
│                  │ calls                 │
│  ┌───────────────▼─────────────────┐     │
│  │       Service Layer             │     │
│  │ AuthService │ OAuthService │... │     │
│  └───────────────┬─────────────────┘     │
│                  │ calls                 │
│  ┌───────────────▼─────────────────┐     │
│  │      Repository Layer           │     │
│  │  UserRepository │ OAuthRepo     │     │
│  └───────────────┬─────────────────┘     │
│                  │                       │
└──────────────────┼───────────────────────┘
                   │
          ┌────────┴────────┐
          ▼                 ▼
    PostgreSQL            Redis
    (persistence)     (blocklist, rate-limit)
```

**Layer responsibilities:**
- **API Layer** — HTTP parsing, input deserialization, response serialization
- **Service Layer** — business rules, orchestration, domain validation
- **Repository Layer** — all database reads/writes (SQLAlchemy sessions)
- **Models** — SQLAlchemy ORM entities (no business logic)

---

## Security Considerations

- Passwords are hashed with **bcrypt** (configurable work factor)
- JWT secrets must be strong, random strings — never reuse across environments
- JWT tokens are short-lived (15 min default); use refresh tokens to extend sessions
- Revoked tokens are stored in **Redis** for immediate invalidation (no waiting for expiry)
- Brute-force protection: accounts lock after 5 consecutive failures for 15 minutes
- PKCE is supported (and recommended) for public OAuth clients
- OAuth client secrets are hashed at rest — returned exactly once at registration
- All sensitive config values come from environment variables — never hard-coded
- Rate limiting applied at the endpoint level; backed by Redis in production

---

## License

MIT
