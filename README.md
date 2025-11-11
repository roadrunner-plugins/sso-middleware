# Auth0 SSO Authentication Middleware for RoadRunner

A comprehensive Auth0 SSO authentication middleware for RoadRunner that provides enterprise-grade authentication capabilities with flexible URL protection patterns and seamless integration with PHP applications.

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
- **PSR7 attributes** injection with comprehensive user profile data
- **Configurable attribute names** for seamless PHP integration
- **Claims extraction** from ID tokens with role mapping
- **Role/permission management** from Auth0 user metadata

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
  middleware: ["auth0"]

auth0:
  domain: "${AUTH0_DOMAIN}"
  client_id: "${AUTH0_CLIENT_ID}"
  client_secret: "${AUTH0_CLIENT_SECRET}"
  # ... see config.example.yaml for full configuration
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

### Accessing User Information

The middleware injects user information into PSR7 request attributes:

```php
<?php
// In your PHP application

// Get the authenticated user context
$userContext = $request->getAttribute('auth0_user_context');

if ($userContext && $userContext['authenticated']) {
    $userId = $userContext['user_id'];
    $profile = $userContext['profile'];
    $email = $profile['email'] ?? null;
    $name = $profile['name'] ?? null;
    $roles = $userContext['roles'] ?? [];
    
    // Check if user has admin role
    $isAdmin = in_array('admin', $roles);
    
    // Access specific claims
    $claims = $userContext['claims'];
    $customClaim = $claims['https://example.com/custom_claim'] ?? null;
} else {
    // User is not authenticated
    // This shouldn't happen on protected routes
}

// Alternative: Access individual attributes (backward compatibility)
$userProfile = $request->getAttribute('auth0_user');    // User profile
$userClaims = $request->getAttribute('auth0_claims');   // JWT claims  
$userRoles = $request->getAttribute('auth0_roles');     // User roles
```

### Working with User Roles

```php
<?php
// Check user permissions
$userContext = $request->getAttribute('auth0_user_context');

function hasRole($userContext, $role) {
    return $userContext['authenticated'] && 
           in_array($role, $userContext['roles'] ?? []);
}

function hasAnyRole($userContext, $roles) {
    if (!$userContext['authenticated']) return false;
    $userRoles = $userContext['roles'] ?? [];
    return !empty(array_intersect($roles, $userRoles));
}

// Usage examples
if (hasRole($userContext, 'admin')) {
    // Admin-only functionality
}

if (hasAnyRole($userContext, ['editor', 'author'])) {
    // Content management functionality
}
```

## Authentication Routes

The middleware handles these authentication routes **automatically** (no PHP code needed):

- **`/auth/login`** - Redirects to Auth0 Universal Login
- **`/auth/callback`** - Handles OAuth callback from Auth0  
- **`/auth/logout`** - Clears session and redirects to Auth0 logout
- **`/auth/user`** - Returns user information as JSON

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

## RPC Management API

The middleware provides an RPC API for external management:

```bash
# Get middleware statistics
curl -X POST http://localhost:6001/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "auth0.GetStats", "params": [{}], "id": 1}'

# Invalidate a user session
curl -X POST http://localhost:6001/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "auth0.InvalidateSession", "params": [{"user_id": "auth0|123456"}], "id": 1}'

# Test URL protection
curl -X POST http://localhost:6001/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "auth0.TestProtection", "params": [{"url": "/admin/users"}], "id": 1}'
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

## Performance Optimizations

### ⚡ Caching & Memory Management
- **In-memory session storage** optimized for RoadRunner
- **Background session cleanup** prevents memory leaks
- **Efficient pattern matching** with compiled regex
- **Connection pooling** for Auth0 API calls
- **Circuit breaker pattern** for external service resilience

### 📊 Monitoring & Metrics
- **Comprehensive logging** with structured fields
- **Session statistics** via RPC API
- **Pattern matching stats** for optimization
- **Error tracking** with operation context

## Production Deployment

### Environment Setup

1. **Configure Auth0 Application:**
   - Set callback URLs: `https://yourdomain.com/auth/callback`
   - Set logout URLs: `https://yourdomain.com`
   - Configure allowed origins for CORS

2. **Update Production Configuration:**

```yaml
auth0:
  domain: "production-tenant.auth0.com"
  callback_url: "https://yourdomain.com/auth/callback"
  logout_url: "https://yourdomain.com"
  session:
    secure: true           # HTTPS-only cookies
    max_age: 7200          # 2 hours
    same_site: "strict"    # Stricter CSRF protection
```

3. **Set Production Environment Variables:**

```bash
AUTH0_DOMAIN=production-tenant.auth0.com
AUTH0_CLIENT_ID=production_client_id
AUTH0_CLIENT_SECRET=production_client_secret
SESSION_SECRET=long_random_production_secret_32_plus_chars
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM spiralscout/roadrunner:2024.1 as rr

# Copy your RoadRunner binary with auth0 plugin
COPY --from=builder /usr/bin/rr /usr/bin/rr

# Copy configuration
COPY .rr.yaml /etc/rr.yaml
COPY .env /etc/.env

EXPOSE 8080
CMD ["/usr/bin/rr", "serve", "-c", "/etc/rr.yaml"]
```

## Troubleshooting

### Common Issues

**1. "Session cookie not found" errors:**
- Check that `session.secret_key` is set and at least 32 characters
- Verify cookie domain/path settings
- Ensure HTTPS in production with `session.secure: true`

**2. "Invalid state parameter" errors:**
- Check that session storage is working correctly
- Verify Auth0 callback URL configuration
- Look for clock synchronization issues

**3. "Pattern matching not working:**
- Test patterns using the RPC API: `auth0.TestProtection`
- Verify regex syntax (Go regex flavor)
- Check pattern precedence (excluded patterns override protected)

**4. Auth0 configuration issues:**
- Verify domain, client ID, and client secret
- Check Auth0 application settings (callback URLs, logout URLs)
- Ensure application type is "Regular Web Application"

### Debug Logging

Enable debug logging to troubleshoot issues:

```yaml
logs:
  level: "debug"
  
auth0:
  # ... your config
```

### RPC Diagnostics

Use RPC commands to diagnose issues:

```bash
# Check middleware status
rr rpc call auth0.GetStats

# Test URL protection
rr rpc call auth0.TestProtection '{"url": "/your/protected/path"}'

# Check active sessions
rr rpc call auth0.GetStats | jq '.active_sessions'
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
