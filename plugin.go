package auth0

import (
	"context"
	"net/http"
	"time"

	rrcontext "github.com/roadrunner-server/context"
	"github.com/roadrunner-server/errors"
	"go.uber.org/zap"
)

const pluginName = "auth0"

// Configurer interface for configuration management
type Configurer interface {
	UnmarshalKey(name string, out interface{}) error
	Has(name string) bool
}

// Logger interface for logging
type Logger interface {
	NamedLogger(name string) *zap.Logger
}

// Plugin represents the Auth0 middleware plugin
type Plugin struct {
	log            *zap.Logger
	config         *Config
	client         *Client
	sessionManager *SessionManager
	urlMatcher     *URLMatcher
	handler        *Handler
	attributeKeys  *AttributeKeys

	// Background cleanup ticker
	cleanupTicker *time.Ticker
	cleanupDone   chan bool
}

// Init initializes the Auth0 middleware plugin
func (p *Plugin) Init(cfg Configurer, log Logger) error {
	const op = errors.Op("auth0_plugin_init")

	// Check if plugin is enabled
	if !cfg.Has(pluginName) {
		return errors.E(op, errors.Disabled)
	}

	// Initialize logger
	p.log = log.NamedLogger(pluginName)

	// Initialize configuration
	p.config = &Config{}
	if err := cfg.UnmarshalKey(pluginName, p.config); err != nil {
		return errors.E(op, err)
	}

	// Set defaults and validate
	p.config.InitDefaults()
	if err := p.config.Validate(); err != nil {
		return errors.E(op, err)
	}

	// Initialize Auth0 client
	client, err := NewClient(p.config)
	if err != nil {
		return errors.E(op, err)
	}
	p.client = client

	// Initialize session manager
	p.sessionManager = NewSessionManager(&p.config.Session)

	// Initialize URL matcher
	urlMatcher, err := NewURLMatcher(&p.config.Protection)
	if err != nil {
		return errors.E(op, err)
	}
	p.urlMatcher = urlMatcher

	// Initialize handler
	p.handler = NewHandler(client, p.sessionManager, p.config, p.log)

	// Initialize attribute keys
	p.attributeKeys = NewAttributeKeys(&p.config.UserAttributes)

	// Start background cleanup goroutine
	p.startCleanupRoutine()

	p.log.Info("Auth0 middleware initialized",
		zap.String("domain", p.config.Domain),
		zap.String("protection_mode", p.config.Protection.Mode),
		zap.Int("protected_patterns", len(p.config.Protection.ProtectedPatterns)),
		zap.Int("excluded_patterns", len(p.config.Protection.ExcludedPatterns)),
		zap.Int("public_routes", len(p.config.Protection.PublicRoutes)))

	return nil
}

// Middleware implements the HTTP middleware interface
func (p *Plugin) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const op = "auth0_middleware"

		// Check if this is an authentication route
		if p.isAuthRoute(r.URL.Path) {
			p.handleAuthRoute(w, r)
			return
		}

		// Check if URL should be protected
		protection := p.urlMatcher.ShouldProtect(r.URL.Path)
		if !protection.Protected {
			// URL is not protected, inject unauthenticated context and continue
			r = p.injectUnauthenticatedContext(r)
			next.ServeHTTP(w, r)
			return
		}

		// URL is protected, check authentication
		session, err := p.sessionManager.GetSessionFromCookie(r)
		if err != nil || session == nil {
			p.log.Debug("unauthenticated request to protected URL",
				zap.String("op", op),
				zap.String("path", r.URL.Path),
				zap.String("reason", protection.Reason),
				zap.Error(err))

			// Redirect to login
			p.redirectToLogin(w, r)
			return
		}

		// User is authenticated, inject context and continue
		r = p.injectAuthenticatedContext(r, session)

		p.log.Debug("authenticated request",
			zap.String("op", op),
			zap.String("path", r.URL.Path),
			zap.String("user_id", session.UserID),
			zap.String("session_id", session.ID))

		next.ServeHTTP(w, r)
	})
}

// Name returns the plugin name
func (p *Plugin) Name() string {
	return pluginName
}

// Weight returns the middleware weight (higher weight = later in chain)
func (p *Plugin) Weight() uint {
	return 100
}

// Stop gracefully stops the plugin
func (p *Plugin) Stop(ctx context.Context) error {
	if p.cleanupTicker != nil {
		p.cleanupTicker.Stop()
	}
	if p.cleanupDone != nil {
		close(p.cleanupDone)
	}

	p.log.Info("Auth0 middleware stopped")
	return nil
}

// isAuthRoute checks if the path is an authentication route
func (p *Plugin) isAuthRoute(path string) bool {
	return p.urlMatcher.IsAuthRoute(path, p.config.Routes.Login) ||
		p.urlMatcher.IsAuthRoute(path, p.config.Routes.Callback) ||
		p.urlMatcher.IsAuthRoute(path, p.config.Routes.Logout) ||
		p.urlMatcher.IsAuthRoute(path, p.config.Routes.UserInfo)
}

// handleAuthRoute handles authentication routes
func (p *Plugin) handleAuthRoute(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case p.urlMatcher.IsAuthRoute(path, p.config.Routes.Login):
		p.handler.HandleLogin(w, r)
	case p.urlMatcher.IsAuthRoute(path, p.config.Routes.Callback):
		p.handler.HandleCallback(w, r)
	case p.urlMatcher.IsAuthRoute(path, p.config.Routes.Logout):
		p.handler.HandleLogout(w, r)
	case p.urlMatcher.IsAuthRoute(path, p.config.Routes.UserInfo):
		p.handler.HandleUserInfo(w, r)
	default:
		// This shouldn't happen, but handle gracefully
		http.NotFound(w, r)
	}
}

// redirectToLogin redirects to the login route
func (p *Plugin) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	loginURL := p.config.Routes.Login

	// Add return_to parameter if not already an auth route
	if !p.isAuthRoute(r.URL.Path) {
		loginURL += "?return_to=" + r.URL.Path
	}

	http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)
}

// injectAuthenticatedContext injects authenticated user context into request
func (p *Plugin) injectAuthenticatedContext(r *http.Request, session *Session) *http.Request {
	userContext := NewUserContext(session)
	attributeMap := userContext.GetAttributeMap(p.attributeKeys)

	// Get existing PSR attributes or create new map
	ctx := r.Context()
	var psrAttributes map[string]interface{}

	if existingAttrs := ctx.Value(rrcontext.PsrContextKey); existingAttrs != nil {
		if attrs, ok := existingAttrs.(map[string]interface{}); ok {
			psrAttributes = attrs
		} else {
			psrAttributes = make(map[string]interface{})
		}
	} else {
		psrAttributes = make(map[string]interface{})
	}

	// Add Auth0 attributes to PSR attributes map
	for key, value := range attributeMap {
		p.log.Debug("injecting user attributes into context",
			zap.String("key", key),
			zap.Any("value", value))
		psrAttributes[key] = value
	}

	// Set the updated PSR attributes back to context
	ctx = context.WithValue(ctx, rrcontext.PsrContextKey, psrAttributes)

	return r.WithContext(ctx)
}

// injectUnauthenticatedContext injects unauthenticated context into request
func (p *Plugin) injectUnauthenticatedContext(r *http.Request) *http.Request {
	userContext := NewUnauthenticatedUserContext()
	attributeMap := userContext.GetAttributeMap(p.attributeKeys)

	// Get existing PSR attributes or create new map
	ctx := r.Context()
	var psrAttributes map[string]interface{}

	if existingAttrs := ctx.Value(rrcontext.PsrContextKey); existingAttrs != nil {
		if attrs, ok := existingAttrs.(map[string]interface{}); ok {
			psrAttributes = attrs
		} else {
			psrAttributes = make(map[string]interface{})
		}
	} else {
		psrAttributes = make(map[string]interface{})
	}

	// Add Auth0 attributes to PSR attributes map
	for key, value := range attributeMap {
		psrAttributes[key] = value
	}

	// Set the updated PSR attributes back to context
	ctx = context.WithValue(ctx, rrcontext.PsrContextKey, psrAttributes)

	return r.WithContext(ctx)
}

// startCleanupRoutine starts background session cleanup
func (p *Plugin) startCleanupRoutine() {
	p.cleanupTicker = time.NewTicker(15 * time.Minute) // Cleanup every 15 minutes
	p.cleanupDone = make(chan bool)

	go func() {
		for {
			select {
			case <-p.cleanupTicker.C:
				p.sessionManager.CleanupExpiredSessions()
				sessionCount := p.sessionManager.GetSessionCount()
				p.log.Debug("cleaned up expired sessions",
					zap.Int("active_sessions", sessionCount))
			case <-p.cleanupDone:
				return
			}
		}
	}()
}

// RPC returns the RPC interface for external API access
func (p *Plugin) RPC() interface{} {
	return &RPC{plugin: p}
}
