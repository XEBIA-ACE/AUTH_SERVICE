# AGENTS.md

## Stack

- **Service:** Auth Service
- **Type:** business
- **Technologies:**
- Node.js with Fastify or Java Spring Boot
- Passport.js (Node) or Spring Security OAuth2 (Java)
- jsonwebtoken / nimbus-jose-jwt for JWT signing and validation
- Redis (session/token cache — C-09)
- PostgreSQL (user identity DB — C-10)
- Flyway for schema migrations
- OpenTelemetry for distributed tracing
- **Responsibilities:**
- Initiate OAuth 2.0 Authorization Code Flow with PKCE redirect to SSO IdP
- Handle SSO IdP callback: exchange authorization code for OIDC tokens
- Validate all OIDC ID token claims (iss, aud, exp, iat, nonce) strictly
- Issue application-scoped JWT access tokens (short-lived, 15 min) and refresh tokens
- Implement refresh token rotation — invalidate old refresh token on each use
- Manage session lifecycle: creation, validation, revocation on logout
- Maintain SSO subject-to-internal user ID mapping with JIT provisioning on first login
- Cache JWKS public keys from IdP with TTL and rotation support
- Store session metadata and token hashes in Redis with TTL-based expiry
- Log all authentication events for audit trail
- Handle IdP error responses and surface meaningful error codes to the API Gateway
- Support token revocation via session cache invalidation on logout

## General Rules

- Always read files in /specs before implementing
- Never implement without acceptance criteria
- Code should be simple and readable
- Avoid overengineering
- The project follows a hexagonal architecture

## Required Workflow

1. Read the specs in the /specs directory
2. Generate tasks.md if it does not exist
3. Implement based on the tasks
4. Create automated tests
5. Validate acceptance criteria

## Testing

- Cover all acceptance criteria
- Tests should be clear and straightforward
- Generated code must reach **90% unit test coverage**

## Constraints

- Do not invent requirements that are not described
- Do not change behavior without updating the spec
