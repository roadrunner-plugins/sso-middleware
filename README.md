# Auth0 SSO Authentication Middleware for RoadRunner

A comprehensive Auth0 SSO authentication middleware for RoadRunner that provides enterprise-grade authentication
capabilities with flexible URL protection patterns and seamless integration with PHP applications.

## Features

### 🔐 Authentication Flow

- **OAuth2 + OpenID Connect** integration with Auth0
- **Universal Login Page** redirection for unauthenticated users
- **Callback handling** for Auth0 responses with CSRF protection
- **Session management** with secure cookie-based storage
- **Token validation** and automatic refresh capabilities
- **Logout flow** with proper Auth0 logout URL redirection

### 🛡️ URL Protection Patterns

- **Global protection** - protect all routes by default
- **Pattern-based protection** - protect specific URL patterns using regex
- **Exclusion patterns** - exclude specific URLs from authentication (health checks, assets)
- **Route-level configuration** - granular per-route authentication requirements
- **Public routes** - explicit route exclusions

### 👤 User Information Injection

- **Single PSR-7 attribute** injection with complete user data in JSON format
- **Simplified PHP integration** - one attribute to check and parse
- **Complete user profile** including ID, session, claims, roles, and profile data
- **Guest user detection** via attribute absence (no attribute = guest user)

### ⚙️ Configuration Management

- **Environment-based configuration** via .rr.yaml and environment variables
- **Flexible session configuration** (timeout, cookie settings, security)
- **Advanced URL pattern configuration** for complex protection rules
- **Auth0 domain and credentials** management

## Installation

1. **Add to your RoadRunner plugin container:**

```go
// container/plugins.go
package container

import (
	// ... other imports
	auth0 "github.com/roadrunner-server/auth0-middleware"
)

func Plugins() []any {
	return []any{
		// ... other plugins
		&auth0.Plugin{},
		// ... other plugins
	}
}
```

2. **Configure in your .rr.yaml:**

```yaml
http:
  middleware: [ "auth0" ]

auth0:
  # Auth0 Application Settings
  domain: "${AUTH0_DOMAIN}"                    # your-tenant.auth0.com
  client_id: "${AUTH0_CLIENT_ID}"              # Your Auth0 application client ID
  client_secret: "${AUTH0_CLIENT_SECRET}"      # Your Auth0 application client secret

  # Application URLs
  callback_url: "http://localhost:8080/_auth/callback"

  # Session Management
  session:
    secret_key: "${SESSION_SECRET}"            # Must be at least 32 characters
```

3. **Set environment variables:**

```bash
cp .env.example .env
# Edit .env with your Auth0 credentials
```

## Configuration

### Basic Configuration

```yaml
auth0:
  # Auth0 Application Settings
  domain: "your-tenant.auth0.com"
  client_id: "your_client_id"
  client_secret: "your_client_secret"

  # Application URLs
  callback_url: "http://localhost:8080/_auth/callback"

  # Session Configuration
  session:
    secret_key: "your_32_plus_character_secret"
    max_age: 3600  # 1 hour

  # URL Protection
  protection:
    mode: "pattern"
    protected_patterns:
      - "^/admin.*"
      - "^/user/profile.*"
    excluded_patterns:
      - "^/public.*"
      - "^/assets.*"
    public_routes:
      - "/"
      - "/about"
```

### Protection Modes

#### 1. Pattern Mode (Recommended)

```yaml
protection:
  mode: "pattern"
  protected_patterns:
    - "^/admin.*"      # Protect admin routes
    - "^/api/private.*" # Protect private API
  excluded_patterns:
    - "^/health.*"     # Health checks bypass auth
    - "^/assets.*"     # Static assets bypass auth
  public_routes:
    - "/"              # Home page is public
    - "/about"         # About page is public
```

#### 2. Global Mode

```yaml
protection:
  mode: "global"       # Protect everything by default
  excluded_patterns:
    - "^/assets.*"     # Only assets bypass auth
  public_routes:
    - "/"              # Only specific routes are public
    - "/contact"
```

#### 3. Disabled Mode (Development)

```yaml
protection:
  mode: "disabled"     # No authentication required
```

## Usage in PHP Applications

### Creating a User DTO/Value Object

For better type safety and code organization, create a User DTO in your PHP application:

```php
<?php
// App/Auth/Auth0User.php

namespace App\Auth;

class Auth0User
{
    private ?array $data;
    
    public function __construct(?string $auth0JSON)
    {
        $this->data = $auth0JSON ? json_decode($auth0JSON, true) : null;
    }
    
    public function isAuthenticated(): bool
    {
        return $this->data !== null;
    }
    
    public function isGuest(): bool
    {
        return $this->data === null;
    }
    
    public function getUserId(): ?string
    {
        return $this->data['user_id'] ?? null;
    }
    
    public function getSessionId(): ?string
    {
        return $this->data['session_id'] ?? null;
    }
    
    public function getEmail(): ?string
    {
        return $this->data['profile']['email'] ?? null;
    }
    
    public function getName(): ?string
    {
        return $this->data['profile']['name'] ?? null;
    }
    
    public function getPicture(): ?string
    {
        return $this->data['profile']['picture'] ?? null;
    }
    
    public function isEmailVerified(): bool
    {
        return $this->data['profile']['email_verified'] ?? false;
    }
    
    public function getRoles(): array
    {
        return $this->data['roles'] ?? [];
    }
    
    public function hasRole(string $role): bool
    {
        return in_array($role, $this->getRoles(), true);
    }
    
    public function hasAnyRole(array $roles): bool
    {
        return !empty(array_intersect($roles, $this->getRoles()));
    }
    
    public function getProfile(): array
    {
        return $this->data['profile'] ?? [];
    }
    
    public function getClaims(): array
    {
        return $this->data['claims'] ?? [];
    }
    
    public function getClaim(string $key, $default = null)
    {
        return $this->data['claims'][$key] ?? $default;
    }
}
```

### Using the User DTO in Middleware

```php
<?php
// App/Middleware/Auth0Middleware.php

namespace App\Middleware;

use App\Auth\Auth0User;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class Auth0Middleware implements MiddlewareInterface
{
    public function process(
        ServerRequestInterface $request, 
        RequestHandlerInterface $handler
    ): ResponseInterface {
        // Get auth0 attribute from RoadRunner middleware
        $auth0JSON = $request->getAttribute('auth0');
        
        // Create user object
        $user = new Auth0User($auth0JSON);
        
        // Inject user object into request for easy access in controllers
        $request = $request->withAttribute('user', $user);
        
        return $handler->handle($request);
    }
}
```

### Using in Controllers

```php
<?php
// App/Controller/UserController.php

namespace App\Controller;

use App\Auth\Auth0User;
use Psr\Http\Message\ServerRequestInterface;

class UserController
{
    public function profile(ServerRequestInterface $request)
    {
        /** @var Auth0User $user */
        $user = $request->getAttribute('user');
        
        if ($user->isGuest()) {
            // Redirect to login or return 401
            return $this->redirect('/_auth/login');
        }
        
        // User is authenticated
        return $this->render('profile', [
            'email' => $user->getEmail(),
            'name' => $user->getName(),
            'picture' => $user->getPicture(),
            'roles' => $user->getRoles(),
        ]);
    }
    
    public function admin(ServerRequestInterface $request)
    {
        /** @var Auth0User $user */
        $user = $request->getAttribute('user');
        
        if (!$user->hasRole('admin')) {
            // Return 403 Forbidden
            return $this->forbidden();
        }
        
        // Admin functionality
        return $this->render('admin/dashboard');
    }
}
```

## Authentication Routes

The middleware handles these authentication routes **automatically** (no PHP code needed):

- **`/_auth/login`** - Redirects to Auth0 Universal Login
- **`/_auth/callback`** - Handles OAuth callback from Auth0
- **`/_auth/logout`** - Clears session and redirects to Auth0 logout
- **`/_auth/user`** - Returns complete user information as JSON

### User Info Endpoint Response

The `/_auth/user` endpoint returns the complete authenticated user data:

```json
{
  "user_id": "auth0|123456789",
  "profile": {
    "sub": "auth0|123456789",
    "name": "John Doe",
    "email": "john@example.com",
    "email_verified": true,
    "picture": "https://...",
    "nickname": "johndoe"
  },
  "claims": {
    "sub": "auth0|123456789",
    "aud": "your_client_id",
    "iss": "https://your-tenant.auth0.com/",
    "iat": 1234567890,
    "exp": 1234571490
  },
  "roles": [
    "admin",
    "user"
  ],
  "session": {
    "id": "sess_abc123",
    "created_at": "2024-01-15T10:30:00Z",
    "expires_at": "2024-01-15T11:30:00Z"
  }
}
```

For unauthenticated requests, returns:

```json
{
  "error": "not_authenticated",
  "message": "User is not authenticated"
}
```

### Custom Authentication Routes

You can customize the authentication route paths:

```yaml
auth0:
  routes:
    login: "/custom/login"
    callback: "/custom/callback"
    logout: "/custom/logout"
    user_info: "/custom/user"
```

When using custom routes, make sure to update the corresponding URLs in your Auth0 application settings and callback URL
in your .rr.yaml.

```yaml
auth0:
  callback_url: "http://localhost:8080/custom/callback"
```

## Security Features

### 🔒 Session Security

- **HTTP-only cookies** prevent XSS attacks
- **Secure cookie flag** for HTTPS environments
- **SameSite attribute** prevents CSRF attacks
- **HMAC-signed cookies** prevent tampering
- **Configurable session timeout** with automatic cleanup

### 🛡️ OAuth Security

- **PKCE (Proof Key for Code Exchange)** for enhanced security
- **State parameter validation** prevents CSRF attacks
- **Nonce validation** for ID tokens
- **Token signature verification** via Auth0 JWKS

### 🔐 Configuration Security

- **Environment variable** usage for sensitive data
- **Configuration validation** on startup prevents misconfigurations
- **Secure defaults** for all security-related settings
- **Open redirect protection** for return URLs

## RPC Methods

The Auth0 middleware exposes RPC methods for programmatic session management and monitoring from your PHP application.
These methods allow you to interact with sessions, check protection rules, and gather statistics.

### Available RPC Methods

#### 1. GetSessionInfo

Retrieves detailed information about a specific session.

**Request:**

```php
<?php
$response = $rpc->call('auth0.GetSessionInfo', [
    'session_id' => 'sess_abc123'
]);
```

**Response:**

```json
{
  "found": true,
  "user_id": "auth0|123456789",
  "profile": {
    "name": "John Doe",
    "email": "john@example.com",
    "picture": "https://..."
  },
  "claims": {
    "sub": "auth0|123456789",
    "aud": "your_client_id",
    "iss": "https://your-tenant.auth0.com/"
  },
  "created_at": "2024-01-15T10:30:00Z",
  "expires_at": "2024-01-15T11:30:00Z"
}
```

**Use Cases:**

- Verify session validity
- Retrieve user information without making additional Auth0 API calls
- Audit session access patterns

---

#### 2. ValidateToken

Validates a session token and returns user information if valid.

**Request:**

```php
<?php
$response = $rpc->call('auth0.ValidateToken', [
    'session_id' => 'sess_abc123'
]);
```

**Response:**

```json
{
  "valid": true,
  "user_id": "auth0|123456789",
  "profile": {
    "name": "John Doe",
    "email": "john@example.com"
  },
  "claims": {
    "sub": "auth0|123456789"
  },
  "expires_at": "2024-01-15T11:30:00Z"
}
```

**Use Cases:**

- Validate session tokens in background jobs
- Check session validity without middleware
- API authentication validation

---

#### 3. InvalidateSession

Invalidates one or more user sessions.

**Request (by session ID):**

```php
<?php
$response = $rpc->call('auth0.InvalidateSession', [
    'session_id' => 'sess_abc123'
]);
```

**Request (by user ID - invalidates all user sessions):**

```php
<?php
$response = $rpc->call('auth0.InvalidateSession', [
    'user_id' => 'auth0|123456789'
]);
```

**Response:**

```json
{
  "success": true,
  "sessions_removed": 2
}
```

**Use Cases:**

- Force logout specific users (security incidents, password changes)
- Implement "logout from all devices" functionality
- Session management in admin panels
- Terminate sessions after permission changes

---

#### 4. GetUserSessions

Retrieves all active sessions for a specific user.

**Request:**

```php
<?php
$response = $rpc->call('auth0.GetUserSessions', [
    'user_id' => 'auth0|123456789'
]);
```

**Response:**

```json
{
  "sessions": [
    {
      "id": "sess_abc123",
      "created_at": "2024-01-15T10:30:00Z",
      "expires_at": "2024-01-15T11:30:00Z",
      "profile": {
        "name": "John Doe",
        "email": "john@example.com"
      }
    },
    {
      "id": "sess_def456",
      "created_at": "2024-01-15T09:00:00Z",
      "expires_at": "2024-01-15T10:00:00Z",
      "profile": {
        "name": "John Doe",
        "email": "john@example.com"
      }
    }
  ]
}
```

**Use Cases:**

- Display active sessions to users (security dashboard)
- Implement "view active devices" feature
- Monitor concurrent session limits
- Session auditing and reporting

---

#### 5. GetStats

Returns comprehensive middleware statistics and configuration.

**Request:**

```php
<?php
$response = $rpc->call('auth0.GetStats', []);
```

**Response:**

```json
{
  "active_sessions": 42,
  "protection_mode": "pattern",
  "pattern_stats": {
    "protected": 5,
    "excluded": 3,
    "public": 2
  },
  "domain": "your-tenant.auth0.com",
  "configured_routes": {
    "login": "/_auth/login",
    "callback": "/_auth/callback",
    "logout": "/_auth/logout",
    "user_info": "/_auth/user"
  }
}
```

**Use Cases:**

- Monitoring dashboard metrics
- Health checks and status pages
- Capacity planning (session counts)
- Configuration verification

---

#### 6. TestProtection

Tests whether a specific URL would be protected by the configured patterns.

**Request:**

```php
<?php
$response = $rpc->call('auth0.TestProtection', [
    'url' => '/admin/users'
]);
```

**Response (protected URL):**

```json
{
  "protected": true,
  "reason": "matched_protected_pattern",
  "pattern": "^/admin.*"
}
```

**Response (public URL):**

```json
{
  "protected": false,
  "reason": "public_route"
}
```

**Response (excluded URL):**

```json
{
  "protected": false,
  "reason": "matched_excluded_pattern",
  "pattern": "^/assets.*"
}
```

**Use Cases:**

- Debug protection configuration
- Validate URL pattern rules
- Testing during development
- Administrative tools for configuration management

---

#### 7. CleanupSessions

Forces immediate cleanup of expired sessions.

**Request:**

```php
<?php
$response = $rpc->call('auth0.CleanupSessions', []);
```

**Response:**

```json
{
  "cleaned": true
}
```

**Use Cases:**

- Manual session cleanup (maintenance operations)
- Free memory during low-traffic periods
- Testing session expiration logic

---

#### 8. GetConfig

Returns sanitized configuration (without secrets).

**Request:**

```php
<?php
$response = $rpc->call('auth0.GetConfig', []);
```

**Response:**

```json
{
  "domain": "your-tenant.auth0.com",
  "callback_url": "http://localhost:8080/_auth/callback",
  "logout_url": "https://your-tenant.auth0.com/v2/logout",
  "protection": {
    "mode": "pattern",
    "protected_patterns": [
      "^/admin.*"
    ],
    "excluded_patterns": [
      "^/assets.*"
    ],
    "public_routes": [
      "/",
      "/about"
    ]
  },
  "routes": {
    "login": "/_auth/login",
    "callback": "/_auth/callback",
    "logout": "/_auth/logout",
    "user_info": "/_auth/user"
  },
  "scopes": [
    "openid",
    "profile",
    "email"
  ],
  "session_max_age": 3600
}
```

**Use Cases:**

- Configuration verification in admin panels
- Debugging configuration issues
- Documentation and support
- Runtime configuration inspection

---

### PHP RPC Client Examples

#### Basic Usage

```php
<?php
use Spiral\Goridge\RPC\RPC;
use Spiral\Goridge\RPC\Codec\JsonCodec;

// Create RPC client
$rpc = new RPC(
    RPC::create('tcp://127.0.0.1:6001'),
    new JsonCodec()
);

// Get session info
$sessionInfo = $rpc->call('auth0.GetSessionInfo', [
    'session_id' => $_COOKIE['session_id'] ?? null
]);

if ($sessionInfo['found']) {
    echo "User: " . $sessionInfo['profile']['name'];
}
```

#### Session Management Service

```php
<?php
namespace App\Service;

use Spiral\Goridge\RPC\RPC;

class Auth0SessionService
{
    public function __construct(
        private RPC $rpc
    ) {}
    
    public function getActiveSessionsForUser(string $userId): array
    {
        $response = $this->rpc->call('auth0.GetUserSessions', [
            'user_id' => $userId
        ]);
        
        return $response['sessions'] ?? [];
    }
    
    public function logoutAllDevices(string $userId): bool
    {
        $response = $this->rpc->call('auth0.InvalidateSession', [
            'user_id' => $userId
        ]);
        
        return $response['success'] ?? false;
    }
    
    public function getSessionCount(): int
    {
        $stats = $this->rpc->call('auth0.GetStats', []);
        return $stats['active_sessions'] ?? 0;
    }
    
    public function isUrlProtected(string $url): bool
    {
        $result = $this->rpc->call('auth0.TestProtection', [
            'url' => $url
        ]);
        
        return $result['protected'] ?? false;
    }
}
```

#### Admin Dashboard Example

```php
<?php
namespace App\Controller;

use App\Service\Auth0SessionService;
use Psr\Http\Message\ServerRequestInterface;

class AdminController
{
    public function __construct(
        private Auth0SessionService $sessionService
    ) {}
    
    public function dashboard(ServerRequestInterface $request)
    {
        $stats = $this->rpc->call('auth0.GetStats', []);
        
        return $this->render('admin/dashboard', [
            'active_sessions' => $stats['active_sessions'],
            'protection_mode' => $stats['protection_mode'],
            'pattern_stats' => $stats['pattern_stats'],
        ]);
    }
    
    public function userSessions(ServerRequestInterface $request)
    {
        $userId = $request->getQueryParams()['user_id'] ?? null;
        
        if (!$userId) {
            return $this->badRequest('User ID required');
        }
        
        $sessions = $this->sessionService->getActiveSessionsForUser($userId);
        
        return $this->json([
            'user_id' => $userId,
            'sessions' => $sessions,
            'count' => count($sessions)
        ]);
    }
    
    public function forceLogout(ServerRequestInterface $request)
    {
        $userId = $request->getParsedBody()['user_id'] ?? null;
        
        if (!$userId) {
            return $this->badRequest('User ID required');
        }
        
        $success = $this->sessionService->logoutAllDevices($userId);
        
        return $this->json([
            'success' => $success,
            'message' => $success 
                ? 'All sessions invalidated' 
                : 'Failed to invalidate sessions'
        ]);
    }
}
```

#### Background Job Example

```php
<?php
namespace App\Job;

use Spiral\Goridge\RPC\RPC;

class SessionCleanupJob
{
    public function __construct(
        private RPC $rpc
    ) {}
    
    public function handle(): void
    {
        // Get current session count
        $stats = $this->rpc->call('auth0.GetStats', []);
        $beforeCount = $stats['active_sessions'] ?? 0;
        
        // Force cleanup
        $this->rpc->call('auth0.CleanupSessions', []);
        
        // Get new session count
        $stats = $this->rpc->call('auth0.GetStats', []);
        $afterCount = $stats['active_sessions'] ?? 0;
        
        $cleaned = $beforeCount - $afterCount;
        
        $this->logger->info("Session cleanup completed", [
            'before' => $beforeCount,
            'after' => $afterCount,
            'cleaned' => $cleaned
        ]);
    }
}
```

### Error Handling

All RPC methods return errors through RoadRunner's RPC error mechanism. Always wrap calls in try-catch blocks:

```php
<?php
use Spiral\Goridge\RPC\Exception\ServiceException;

try {
    $response = $rpc->call('auth0.GetSessionInfo', [
        'session_id' => $sessionId
    ]);
    
    if (!$response['found']) {
        // Session not found
        return $this->unauthorized('Invalid session');
    }
    
    // Process response
} catch (ServiceException $e) {
    // RPC communication error
    $this->logger->error('Auth0 RPC error', [
        'error' => $e->getMessage()
    ]);
    
    return $this->serverError('Authentication service unavailable');
}
```

## License

This middleware is licensed under the MIT License. See LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## Support

For issues and questions:

- Create an issue on GitHub
- Check the troubleshooting section
- Review Auth0 documentation for application setup
