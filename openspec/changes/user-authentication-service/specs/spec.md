# User Authentication Service - Technical Specification

## Purpose

The User Authentication Service provides secure user authentication and session management capabilities for the Online Commerce Platform. It implements OAuth 2.0 and JWT-based authentication patterns to ensure secure access control across all platform services.

## Requirements

### Requirement 1: User Registration Management
The service SHALL provide secure user registration capabilities with proper validation and security measures.

#### Scenario 1.1: Successful User Registration
**Given** a new user provides valid email and password
**When** they submit a registration request
**Then** the system SHALL validate email format and password strength
**And** hash the password using bcrypt with appropriate salt rounds
**And** store user credentials in PostgreSQL database
**And** generate a JWT token for immediate authentication
**And** return HTTP 201 with user ID and token

#### Scenario 1.2: Duplicate Email Registration
**Given** a user attempts to register with an existing email
**When** they submit the registration request
**Then** the system SHALL check email uniqueness in the database
**And** return HTTP 409 with "User already exists" error message

### Requirement 2: User Authentication
The service SHALL authenticate users through multiple methods with proper security controls.

#### Scenario 2.1: Successful Email/Password Login
**Given** an existing user provides valid credentials
**When** they submit a login request
**Then** the system SHALL retrieve user record by email
**And** verify password against stored hash using bcrypt
**And** generate a new JWT token with user claims
**And** cache session data in Redis with TTL
**And** return HTTP 200 with authentication token

#### Scenario 2.2: Invalid Credentials
**Given** a user provides incorrect email or password
**When** they attempt to login
**Then** the system SHALL return HTTP 401 with generic error message
**And** implement rate limiting to prevent brute force attacks
**And** log the failed attempt for security monitoring

### Requirement 3: OAuth Integration
The service SHALL support third-party OAuth providers for social authentication.

#### Scenario 3.1: OAuth Provider Authentication
**Given** a user chooses OAuth login with supported provider
**When** they complete the OAuth authorization flow
**Then** the system SHALL validate the OAuth token with the provider
**And** retrieve user profile information from OAuth provider
**And** create or update user record based on OAuth profile
**And** generate platform JWT token
**And** return authentication response

### Requirement 4: Token Management
The service SHALL provide JWT token generation and validation capabilities.

#### Scenario 4.1: Token Validation
**Given** a service presents a JWT token for validation
**When** token validation is requested
**Then** the system SHALL verify token signature using secret key
**And** check token expiration timestamp
**And** validate token claims and structure
**And** return validation result with user context

## Technologies and Runtime Stack

- **Runtime**: Node.js with Express.js framework
- **Authentication**: OAuth 2.0, JWT (JSON Web Tokens)
- **Database**: PostgreSQL for persistent user data storage
- **Caching**: Redis for session data and performance optimization
- **Security**: bcrypt for password hashing, HTTPS for transport security
- **Containerization**: Docker containers orchestrated by Kubernetes
- **Monitoring**: Prometheus metrics, Grafana dashboards
- **Logging**: Structured logging with ELK Stack integration

## Service Components

### Auth Controller (C-02)
- **Purpose**: Handles incoming HTTP requests for authentication operations
- **Technologies**: Express.js, middleware for request validation
- **Responsibilities**: 
  - Route authentication requests to appropriate handlers
  - Implement request validation and sanitization
  - Handle HTTP response formatting and error handling
  - Apply rate limiting and security middleware

### User Service (C-03)
- **Purpose**: Contains core business logic for user operations
- **Technologies**: Node.js, business logic layer
- **Responsibilities**:
  - Orchestrate user registration and login workflows
  - Coordinate with repository and external services
  - Implement business rules and validation
  - Handle authentication state management

### User Repository (C-04)
- **Purpose**: Data access layer for user-related database operations
- **Technologies**: PostgreSQL client, connection pooling
- **Responsibilities**:
  - Execute database queries for user CRUD operations
  - Handle database connection management
  - Implement data mapping and transformation
  - Ensure data consistency and transaction management

### OAuth Adapter (C-05)
- **Purpose**: Integration layer for third-party OAuth providers
- **Technologies**: OAuth 2.0 client libraries
- **Responsibilities**:
  - Handle OAuth authorization flows
  - Validate OAuth tokens with providers
  - Retrieve user profile data from OAuth providers
  - Map OAuth profiles to internal user model

### JWT Processor (C-06)
- **Purpose**: JWT token creation and validation service
- **Technologies**: JWT libraries, cryptographic functions
- **Responsibilities**:
  - Generate JWT tokens with appropriate claims
  - Validate token signatures and expiration
  - Handle token refresh operations
  - Manage signing keys and security

### Cache Manager (C-07)
- **Purpose**: Session data caching for performance optimization
- **Technologies**: Redis client, caching strategies
- **Responsibilities**:
  - Store and retrieve session data
  - Implement cache TTL and eviction policies
  - Handle cache invalidation scenarios
  - Optimize database load through intelligent caching

## API Endpoints

### POST /auth/register
- **Purpose**: Register a new user account
- **Input**: RegistrationRequest (email, password)
- **Output**: ApiResponse with user ID and JWT token
- **Main Flow**:
  1. Validate email format and password strength
  2. Check email uniqueness in database
  3. Hash password using bcrypt
  4. Create user record in PostgreSQL
  5. Generate JWT token
  6. Return success response with token

### POST /auth/login
- **Purpose**: Authenticate existing user
- **Input**: LoginRequest (email, password)
- **Output**: ApiResponse with JWT token
- **Main Flow**:
  1. Retrieve user by email from database
  2. Verify password against stored hash
  3. Generate new JWT token
  4. Cache session data in Redis
  5. Return authentication token

### POST /auth/refresh
- **Purpose**: Refresh authentication token
- **Input**: Current JWT token
- **Output**: New JWT token
- **Main Flow**:
  1. Validate current token
  2. Check token expiration and refresh eligibility
  3. Generate new token with extended expiration
  4. Update cached session data
  5. Return new token

### GET /health
- **Purpose**: Service health check endpoint
- **Input**: None
- **Output**: Health status
- **Main Flow**:
  1. Check database connectivity
  2. Verify Redis cache availability
  3. Validate service dependencies
  4. Return health status

## Data Models

### User
- **Fields**: 
  - id (string, UUID): Unique user identifier
  - email (string, email format): User email address
  - passwordHash (string): bcrypt hashed password
  - createdAt (timestamp): Account creation time
  - updatedAt (timestamp): Last update time
- **Invariants**: 
  - Email must be unique across all users
  - Password hash must never be null for local accounts
  - Email format must be valid

### RegistrationRequest
- **Fields**:
  - email (string, required): Valid email address
  - password (string, required): Minimum 8 characters with complexity requirements
- **Validation**: Email format, password strength requirements

### LoginRequest
- **Fields**:
  - email (string, required): User email address
  - password (string, required): User password
- **Validation**: Required field validation, format checking

### OAuthRequest
- **Fields**:
  - provider (string, required): OAuth provider name (google, facebook, github)
  - token (string, required): OAuth access token from provider
- **Validation**: Supported provider validation, token format

### ApiResponse
- **Fields**:
  - status (string): Success or error status
  - data (object): Response payload (user info, tokens)
  - message (string): Human-readable message
  - timestamp (string): Response timestamp

## External System Interactions

### PostgreSQL Database
- **Protocol**: TCP/PostgreSQL wire protocol
- **Operations**: User CRUD operations, transaction management
- **Error Handling**: Connection retry logic, transaction rollback
- **Security**: Connection pooling, prepared statements to prevent SQL injection

### Redis Cache
- **Protocol**: Redis protocol over TCP
- **Operations**: Session storage, cache retrieval, TTL management
- **Error Handling**: Cache miss fallback to database, connection retry
- **Performance**: Connection pooling, pipeline operations for bulk operations

### OAuth Providers
- **Protocol**: HTTPS/REST API calls
- **Operations**: Token validation, user profile retrieval
- **Error Handling**: Provider timeout handling, fallback mechanisms
- **Security**: HTTPS only, token validation, rate limiting compliance

## Key Flows

### User Registration Flow
1. Receive registration request with email and password
2. Validate input format and business rules
3. Check email uniqueness in PostgreSQL database
4. Hash password using bcrypt with salt
5. Insert new user record in database transaction
6. Generate JWT token with user claims
7. Cache initial session data in Redis
8. Return success response with user ID and token
9. Log registration event for analytics
10. Send welcome notification (async)

### User Login Flow
1. Receive login request with credentials
2. Validate input format and sanitize data
3. Query user record by email from PostgreSQL
4. Verify password hash using bcrypt comparison
5. Check account status and restrictions
6. Generate new JWT token with fresh expiration
7. Update session cache in Redis with new token
8. Log successful authentication event
9. Return authentication response with token
10. Update last login timestamp (async)

### OAuth Authentication Flow
1. Receive OAuth callback with provider token
2. Validate OAuth token with provider API
3. Retrieve user profile from OAuth provider
4. Check if user exists by OAuth provider ID
5. Create new user or update existing user record
6. Generate platform JWT token
7. Cache session data with OAuth provider info
8. Return authentication response
9. Log OAuth authentication event
10. Sync user profile data (async)

### Token Validation Flow
1. Receive token validation request from service
2. Extract JWT token from request headers
3. Verify token signature using secret key
4. Check token expiration and validity
5. Validate token claims and structure
6. Retrieve cached session data if available
7. Return validation result with user context
8. Log token usage for security monitoring

### Session Management Flow
1. Monitor active sessions in Redis cache
2. Implement session TTL and automatic expiration
3. Handle session invalidation requests
4. Clean up expired sessions periodically
5. Maintain session statistics for monitoring