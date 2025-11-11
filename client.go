package auth0

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Client wraps Auth0 OAuth2 and OIDC functionality
type Client struct {
	provider *oidc.Provider
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewClient creates a new Auth0 client
func NewClient(cfg *Config) (*Client, error) {
	const op = "auth0_client_init"

	// Create OIDC provider
	provider, err := oidc.NewProvider(
		context.Background(),
		"https://"+cfg.Domain+"/",
	)
	if err != nil {
		return nil, &ClientError{Op: op, Err: err, Message: "failed to create OIDC provider"}
	}

	// Configure OAuth2
	oauth2Config := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.CallbackURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}

	// Create ID token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	return &Client{
		provider: provider,
		config:   oauth2Config,
		verifier: verifier,
	}, nil
}

// GenerateAuthURL generates the authorization URL with state
func (c *Client) GenerateAuthURL(state string) string {
	return c.config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// ExchangeCode exchanges authorization code for tokens
func (c *Client) ExchangeCode(ctx context.Context, code string) (*oauth2.Token, error) {
	const op = "auth0_exchange_code"

	token, err := c.config.Exchange(ctx, code)
	if err != nil {
		return nil, &ClientError{Op: op, Err: err, Message: "failed to exchange authorization code"}
	}

	return token, nil
}

// VerifyIDToken verifies and returns the ID token
func (c *Client) VerifyIDToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {
	const op = "auth0_verify_token"

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, &ClientError{Op: op, Message: "no id_token field in oauth2 token"}
	}

	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, &ClientError{Op: op, Err: err, Message: "failed to verify ID token"}
	}

	return idToken, nil
}

// ExtractClaims extracts claims from ID token
func (c *Client) ExtractClaims(idToken *oidc.IDToken) (map[string]interface{}, error) {
	const op = "auth0_extract_claims"

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, &ClientError{Op: op, Err: err, Message: "failed to extract claims"}
	}

	return claims, nil
}

// GenerateState generates a cryptographically secure random state
func GenerateState() (string, error) {
	const op = "auth0_generate_state"

	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", &ClientError{Op: op, Err: err, Message: "failed to generate random state"}
	}

	return base64.URLEncoding.EncodeToString(b), nil
}

// GenerateLogoutURL generates Auth0 logout URL
func GenerateLogoutURL(domain, clientID, returnTo string) string {
	return "https://" + domain + "/v2/logout?client_id=" + clientID + "&returnTo=" + returnTo
}

// ClientError represents Auth0 client errors
type ClientError struct {
	Op      string
	Err     error
	Message string
}

func (e *ClientError) Error() string {
	if e.Err != nil {
		return e.Op + ": " + e.Message + ": " + e.Err.Error()
	}
	return e.Op + ": " + e.Message
}

func (e *ClientError) Unwrap() error {
	return e.Err
}

// IsNetworkError checks if the error is a network-related error
func IsNetworkError(err error) bool {
	var clientErr *ClientError
	if errors.As(err, &clientErr) {
		return clientErr.Op == "auth0_client_init" ||
			clientErr.Op == "auth0_exchange_code" ||
			(clientErr.Err != nil && isNetworkError(clientErr.Err))
	}
	return false
}

func isNetworkError(err error) bool {
	// Check for common network error indicators
	switch err := err.(type) {
	case interface{ Timeout() bool }:
		return err.Timeout()
	case interface{ Temporary() bool }:
		return err.Temporary()
	default:
		// Check for DNS errors, connection refused, etc.
		errStr := err.Error()
		return contains(errStr, "connection refused") ||
			contains(errStr, "no such host") ||
			contains(errStr, "timeout") ||
			contains(errStr, "network is unreachable")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr || (len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
				s[len(s)-len(substr):] == substr ||
				indexSubstring(s, substr) >= 0)))
}

func indexSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
