# User Authentication Service - Technical Design

## Architecture Overview

The User Authentication Service follows a layered microservice architecture pattern with clear separation of concerns across presentation, business logic, and data access layers. The service is designed for high availability, scalability, and security within the broader Online Commerce Platform ecosystem.

### Architectural Patterns
- **Microservice Architecture**: Independent service with dedicated database and caching layer
- **Layered Architecture**: Clear separation between controllers, services, and repositories
- **Circuit Breaker Pattern**: Resilient integration with external OAuth providers
- **CQRS Pattern**: Optimized read/write operations for user data
- **Event-Driven Architecture**: Asynchronous communication via Kafka for user events

## Technical Approach

### Authentication Strategy
The service implements a hybrid authentication approach combining traditional email/password authentication with modern OAuth 2.0 integration:

1. **Local Authentication**: bcrypt password hashing with configurable salt rounds
2. **OAuth Integration**: Support for multiple providers (Google, Facebook, GitHub)
3. **JWT Token Management**: Stateless token-based session management
4. **Session Caching**: Redis-based caching for performance optimization

### Security Implementation
- **Transport Security**: HTTPS/TLS 1.3 for all communications
- **Password Security**: bcrypt hashing with minimum 12 salt rounds
- **Token Security**: JWT with RS256 signing algorithm and 15-minute expiration
- **Rate Limiting**: Exponential backoff for failed authentication attempts
- **Input Validation**: Comprehensive sanitization and validation middleware

### Performance Optimization
- **Connection Pooling**: PostgreSQL and Redis connection pools
- **Caching Strategy**: Multi-level caching with Redis and in-memory caches
- **Async Processing**: Non-blocking I/O for external API calls
- **Database Optimization**: Indexed queries and prepared statements

## Data Flow Architecture

### Registration Flow
```
Client Request → API Gateway → Auth Controller → User Service → User Repository → PostgreSQL
                                                      ↓
                                              JWT Processor → Cache Manager → Redis
```

### Authentication Flow
```
Client Request → API Gateway → Auth Controller → User Service → User Repository → PostgreSQL
                                                      ↓              ↓
                                              JWT Processor    Cache Manager → Redis
                                                      ↓
                                              OAuth Adapter → External OAuth Providers
```

### Token Validation Flow
```
Service Request → Auth Controller → JWT Processor → Cache Manager → Redis
                                         ↓
                                  Token Validation Response
```

## Component Design

### Auth Controller Layer
- **Request Handling**: Express.js middleware for HTTP request processing
- **Input Validation**: Joi schema validation for request payloads
- **Error Handling**: Centralized error handling with proper HTTP status codes
- **Rate Limiting**: Redis-based rate limiting with sliding window algorithm
- **Logging**: Structured logging with correlation IDs for request tracing

### Business Logic Layer
- **User Service**: Core authentication business logic and workflow orchestration
- **Password Service**: Secure password hashing and verification using bcrypt
- **Token Service**: JWT generation, validation, and refresh token management
- **OAuth Service**: Third-party provider integration and profile mapping

### Data Access Layer
- **User Repository**: PostgreSQL data access with connection pooling
- **Cache Repository**: Redis operations with TTL management and fallback strategies
- **Migration Management**: Database schema versioning and migration scripts

### Integration Layer
- **OAuth Adapters**: Provider-specific implementations for Google, Facebook, GitHub
- **Event Publishers**: Kafka message publishing for user lifecycle events
- **Health Checks**: Comprehensive health monitoring for dependencies

## API Design Decisions

### RESTful API Design
- **Resource-based URLs**: `/auth/register`, `/auth/login`, `/auth/refresh`
- **HTTP Method Semantics**: POST for state-changing operations, GET for health checks
- **Status Code Standards**: Proper HTTP status codes (200, 201, 400, 401, 409, 500)
- **Content Negotiation**: JSON request/response format with proper Content-Type headers

### Error Response Format
```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password",
    "timestamp": "2024-01-15T10:30:00Z",
    "correlationId": "req-123456"
  }
}
```

### Success Response Format
```json
{
  "data": {
    "userId": "user-uuid",
    "token": "jwt-token",
    "expiresAt": "2024-01-15T11:30:00Z"
  },
  "status": "success",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Database Design

### User Table Schema
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    oauth_provider VARCHAR(50),
    oauth_provider_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_oauth ON users(oauth_provider, oauth_provider_id);
```

### Session Cache Schema (Redis)
```
Key: session:{userId}
Value: {
  "userId": "uuid",
  "email": "user@example.com",
  "tokenHash": "hash",
  "createdAt": "timestamp",
  "lastAccess": "timestamp"
}
TTL: 900 seconds (15 minutes)
```

## Integration Architecture

### API Gateway Integration
- **Request Routing**: Gateway routes `/auth/*` requests to authentication service
- **Load Balancing**: Round-robin distribution across service instances
- **Circuit Breaker**: Fail-fast behavior when service is unavailable
- **Request/Response Transformation**: Header injection and response formatting

### External OAuth Provider Integration
- **Provider Abstraction**: Common interface for different OAuth providers
- **Token Validation**: Real-time token verification with provider APIs
- **Profile Mapping**: Standardized user profile extraction from provider responses
- **Error Handling**: Graceful degradation when providers are unavailable

### Event-Driven Integration
- **User Registration Events**: Published to `user.registered` Kafka topic
- **Authentication Events**: Published to `user.authenticated` Kafka topic
- **Security Events**: Published to `security.events` topic for monitoring

## Deployment Architecture

### Container Configuration
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

### Kubernetes Deployment
- **Replica Set**: 3 replicas for high availability
- **Resource Limits**: 512Mi memory, 500m CPU per pod
- **Health Checks**: Liveness and readiness probes on `/health` endpoint
- **Service Discovery**: Kubernetes service with ClusterIP for internal communication

### Environment Configuration
- **Development**: Single instance with local PostgreSQL and Redis
- **Staging**: 2 replicas with managed database services
- **Production**: 3+ replicas with multi-AZ database deployment and Redis cluster

## Monitoring and Observability

### Metrics Collection
- **Application Metrics**: Authentication success/failure rates, response times
- **System Metrics**: CPU, memory, network utilization
- **Business Metrics**: User registration rates, OAuth provider usage
- **Security Metrics**: Failed login attempts, suspicious activity patterns

### Logging Strategy
- **Structured Logging**: JSON format with consistent field naming
- **Log Levels**: ERROR, WARN, INFO, DEBUG with appropriate filtering
- **Correlation IDs**: Request tracing across service boundaries
- **Security Logging**: Authentication events, access patterns, security violations

### Alerting Rules
- **High Error Rate**: >5% authentication failures in 5-minute window
- **Response Time**: >2 second average response time
- **Database Connectivity**: Connection pool exhaustion or database unavailability
- **Security Alerts**: Brute force attack detection, unusual access patterns