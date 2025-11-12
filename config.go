package auth0

import (
	"time"
)

// Config represents the Auth0 middleware configuration
type Config struct {
	// Auth0 Configuration
	Domain       string `mapstructure:"domain" json:"domain"`
	ClientID     string `mapstructure:"client_id" json:"client_id"`
	ClientSecret string `mapstructure:"client_secret" json:"client_secret"`

	// Callback Configuration
	CallbackURL string `mapstructure:"callback_url" json:"callback_url"`
	LogoutURL   string `mapstructure:"logout_url" json:"logout_url"`

	// Session Configuration
	Session SessionConfig `mapstructure:"session" json:"session"`

	// URL Protection Configuration
	Protection ProtectionConfig `mapstructure:"protection" json:"protection"`

	// User Attribute Configuration
	UserAttributes UserAttributesConfig `mapstructure:"user_attributes" json:"user_attributes"`

	// Auth0 Scopes
	Scopes []string `mapstructure:"scopes" json:"scopes"`

	// Authentication Routes (handled by RoadRunner middleware)
	Routes RoutesConfig `mapstructure:"routes" json:"routes"`
}

// SessionConfig represents session management configuration
type SessionConfig struct {
	CookieName string `mapstructure:"cookie_name" json:"cookie_name"`
	SecretKey  string `mapstructure:"secret_key" json:"secret_key"`
	MaxAge     int    `mapstructure:"max_age" json:"max_age"`
	Secure     bool   `mapstructure:"secure" json:"secure"`
	HTTPOnly   bool   `mapstructure:"http_only" json:"http_only"`
	SameSite   string `mapstructure:"same_site" json:"same_site"`
}

// ProtectionConfig represents URL protection configuration
type ProtectionConfig struct {
	Mode              string   `mapstructure:"mode" json:"mode"`
	ProtectedPatterns []string `mapstructure:"protected_patterns" json:"protected_patterns"`
	ExcludedPatterns  []string `mapstructure:"excluded_patterns" json:"excluded_patterns"`
	PublicRoutes      []string `mapstructure:"public_routes" json:"public_routes"`
}

// UserAttributesConfig represents user attribute injection configuration
type UserAttributesConfig struct {
	ProfileAttribute string `mapstructure:"profile_attribute" json:"profile_attribute"`
	ClaimsAttribute  string `mapstructure:"claims_attribute" json:"claims_attribute"`
	RolesAttribute   string `mapstructure:"roles_attribute" json:"roles_attribute"`
}

// RoutesConfig represents authentication routes configuration
type RoutesConfig struct {
	Login    string `mapstructure:"login" json:"login"`
	Callback string `mapstructure:"callback" json:"callback"`
	Logout   string `mapstructure:"logout" json:"logout"`
	UserInfo string `mapstructure:"user_info" json:"user_info"`
}

// InitDefaults sets default values for configuration
func (c *Config) InitDefaults() {
	// Auth0 defaults
	if c.CallbackURL == "" {
		c.CallbackURL = "http://localhost:8080/_auth/callback"
	}
	if c.LogoutURL == "" {
		c.LogoutURL = "http://localhost:8080/_auth/logout"
	}

	// Session defaults
	if c.Session.CookieName == "" {
		c.Session.CookieName = "auth0_session"
	}
	if c.Session.MaxAge == 0 {
		c.Session.MaxAge = 3600 // 1 hour
	}
	if c.Session.SameSite == "" {
		c.Session.SameSite = "lax"
	}
	c.Session.HTTPOnly = true // Always HTTP-only for security

	// Protection defaults
	if c.Protection.Mode == "" {
		c.Protection.Mode = "disabled"
	}

	// User attributes defaults
	if c.UserAttributes.ProfileAttribute == "" {
		c.UserAttributes.ProfileAttribute = "auth0_user"
	}
	if c.UserAttributes.ClaimsAttribute == "" {
		c.UserAttributes.ClaimsAttribute = "auth0_claims"
	}
	if c.UserAttributes.RolesAttribute == "" {
		c.UserAttributes.RolesAttribute = "auth0_roles"
	}

	// Scopes defaults
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "profile", "email"}
	}

	// Routes defaults
	if c.Routes.Login == "" {
		c.Routes.Login = "/_auth/login"
	}
	if c.Routes.Callback == "" {
		c.Routes.Callback = "/_auth/callback"
	}
	if c.Routes.Logout == "" {
		c.Routes.Logout = "/_auth/logout"
	}
	if c.Routes.UserInfo == "" {
		c.Routes.UserInfo = "/_auth/user"
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Domain == "" {
		return &ConfigError{Field: "domain", Message: "Auth0 domain is required"}
	}
	if c.ClientID == "" {
		return &ConfigError{Field: "client_id", Message: "Auth0 client ID is required"}
	}
	if c.ClientSecret == "" {
		return &ConfigError{Field: "client_secret", Message: "Auth0 client secret is required"}
	}
	if c.Session.SecretKey == "" {
		return &ConfigError{Field: "session.secret_key", Message: "Session secret key is required"}
	}
	if len(c.Session.SecretKey) < 32 {
		return &ConfigError{Field: "session.secret_key", Message: "Session secret key must be at least 32 characters"}
	}

	// Validate protection mode
	validModes := map[string]bool{
		"global":   true,
		"pattern":  true,
		"disabled": true,
	}
	if !validModes[c.Protection.Mode] {
		return &ConfigError{
			Field:   "protection.mode",
			Message: "Protection mode must be one of: global, pattern, disabled",
		}
	}

	// Validate SameSite
	validSameSite := map[string]bool{
		"strict": true,
		"lax":    true,
		"none":   true,
	}
	if !validSameSite[c.Session.SameSite] {
		return &ConfigError{
			Field:   "session.same_site",
			Message: "SameSite must be one of: strict, lax, none",
		}
	}

	return nil
}

// ConfigError represents a configuration error
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return "config error in field '" + e.Field + "': " + e.Message
}

// GetMaxAgeDuration returns MaxAge as time.Duration
func (s *SessionConfig) GetMaxAgeDuration() time.Duration {
	return time.Duration(s.MaxAge) * time.Second
}
