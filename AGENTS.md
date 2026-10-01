# AGENTS.md

## Stack

- **Service:** Identity & User Service
- **Type:** business
- **Technologies:**
- Java Spring Boot or Node.js NestJS (TypeScript)
- Argon2id / bcrypt (password hashing)
- JWT / jjwt / jsonwebtoken (token handling)
- Resilience4j (circuit breaker, retry)
- PostgreSQL 15+ via JDBC / TypeORM / Hibernate (primary write + replica read)
- PgBouncer (connection pooling)
- Redis 7+ (OTP/token TTL store, rate-limit counters)
- Apache Kafka producer (Outbox Pattern via Debezium CDC or polling relay)
- OpenTelemetry (distributed tracing, correlation IDs)
- Bean Validation / class-validator (input validation)
- Docker / Kubernetes (HPA for horizontal scaling)
- Flyway / Liquibase (schema migrations)
- **Responsibilities:**
- Handle user registration via email-based and mobile-number-based strategies (Strategy Pattern)
- Perform server-side validation and sanitization of all registration inputs
- Hash passwords using Argon2id/bcrypt before persistence — never store plaintext credentials
- Generate, store (Redis TTL), and validate OTP codes for mobile registration and email verification tokens
- Manage account state machine transitions: PENDING_VERIFICATION → ACTIVE → SUSPENDED
- Enforce business rules: duplicate email/mobile detection, password policy, OTP attempt limits
- Delegate JWT access and refresh token issuance to the OAuth 2.0/OIDC Provider (Keycloak/Auth0)
- Publish domain events (UserRegistered, OTPRequested, AccountVerified, RegistrationFailed) via Outbox Pattern
- Expose CQRS-separated command endpoints (writes to primary) and query endpoints (reads from replica)
- Implement circuit breakers (Resilience4j) around Redis, PostgreSQL, and OIDC provider calls
- Mask PII in all log outputs; encrypt PII fields at rest (AES-256)

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
