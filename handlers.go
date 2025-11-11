package auth0

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Handler manages authentication route handling
type Handler struct {
	client         *Client
	sessionManager *SessionManager
	config         *Config
	logger         *zap.Logger
}

// NewHandler creates a new authentication handler
func NewHandler(client *Client, sessionManager *SessionManager, config *Config, logger *zap.Logger) *Handler {
	return &Handler{
		client:         client,
		sessionManager: sessionManager,
		config:         config,
		logger:         logger,
	}
}

// HandleLogin handles the login route
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	const op = "auth0_handle_login"

	// Generate state for CSRF protection
	state, err := GenerateState()
	if err != nil {
		h.logger.Error("failed to generate state", zap.String("op", op), zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create temporary session to store state
	tempSession, err := h.sessionManager.CreateTempSession(state)
	if err != nil {
		h.logger.Error("failed to create temp session", zap.String("op", op), zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set temporary session cookie
	if err := h.sessionManager.SetSessionCookie(w, tempSession); err != nil {
		h.logger.Error("failed to set session cookie", zap.String("op", op), zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate Auth0 authorization URL
	authURL := h.client.GenerateAuthURL(state)

	h.logger.Debug("redirecting to Auth0 login",
		zap.String("op", op),
		zap.String("state", state),
		zap.String("session_id", tempSession.ID))

	// Redirect to Auth0
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// HandleCallback handles the OAuth callback
func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	const op = "auth0_handle_callback"

	// Get session from cookie
	session, err := h.sessionManager.GetSessionFromCookie(r)
	if err != nil {
		h.logger.Error("failed to get session from cookie", zap.String("op", op), zap.Error(err))
		http.Error(w, "Invalid session", http.StatusBadRequest)
		return
	}

	// Validate state parameter
	state := r.URL.Query().Get("state")
	if !h.sessionManager.ValidateState(session.ID, state) {
		h.logger.Error("invalid state parameter",
			zap.String("op", op),
			zap.String("expected_state", session.State),
			zap.String("received_state", state))
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Get authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		// Check for error parameters
		errorCode := r.URL.Query().Get("error")
		errorDesc := r.URL.Query().Get("error_description")

		h.logger.Error("authorization error",
			zap.String("op", op),
			zap.String("error", errorCode),
			zap.String("error_description", errorDesc))

		http.Error(w, "Authorization failed: "+errorDesc, http.StatusBadRequest)
		return
	}

	// Exchange code for tokens
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	token, err := h.client.ExchangeCode(ctx, code)
	if err != nil {
		h.logger.Error("failed to exchange code for token", zap.String("op", op), zap.Error(err))
		if IsNetworkError(err) {
			http.Error(w, "Authentication service temporarily unavailable", http.StatusServiceUnavailable)
		} else {
			http.Error(w, "Authentication failed", http.StatusUnauthorized)
		}
		return
	}

	// Verify ID token
	idToken, err := h.client.VerifyIDToken(ctx, token)
	if err != nil {
		h.logger.Error("failed to verify ID token", zap.String("op", op), zap.Error(err))
		http.Error(w, "Token verification failed", http.StatusUnauthorized)
		return
	}

	// Extract claims
	claims, err := h.client.ExtractClaims(idToken)
	if err != nil {
		h.logger.Error("failed to extract claims", zap.String("op", op), zap.Error(err))
		http.Error(w, "Failed to extract user information", http.StatusInternalServerError)
		return
	}

	// Extract user ID
	userID, ok := claims["sub"].(string)
	if !ok {
		h.logger.Error("missing or invalid user ID in claims", zap.String("op", op))
		http.Error(w, "Invalid user information", http.StatusInternalServerError)
		return
	}

	// Create user profile
	profile := h.extractProfile(claims)

	// Delete temporary session
	h.sessionManager.DeleteSession(session.ID)

	// Create authenticated session
	authSession, err := h.sessionManager.CreateSession(userID, profile, claims)
	if err != nil {
		h.logger.Error("failed to create authenticated session", zap.String("op", op), zap.Error(err))
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Set authenticated session cookie
	if err := h.sessionManager.SetSessionCookie(w, authSession); err != nil {
		h.logger.Error("failed to set authenticated session cookie", zap.String("op", op), zap.Error(err))
		http.Error(w, "Failed to set session", http.StatusInternalServerError)
		return
	}

	h.logger.Info("user authenticated successfully",
		zap.String("op", op),
		zap.String("user_id", userID),
		zap.String("session_id", authSession.ID))

	// Redirect to application (or return to originally requested URL)
	redirectURL := h.getRedirectURL(r)
	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

// HandleLogout handles the logout route
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	const op = "auth0_handle_logout"

	// Get session from cookie
	session, err := h.sessionManager.GetSessionFromCookie(r)
	if err != nil {
		h.logger.Debug("no session found during logout", zap.String("op", op))
		// Even if no session, still redirect to Auth0 logout
	} else {
		// Delete session
		h.sessionManager.DeleteSession(session.ID)
		h.logger.Debug("user logged out",
			zap.String("op", op),
			zap.String("user_id", session.UserID),
			zap.String("session_id", session.ID))
	}

	// Clear session cookie
	h.sessionManager.ClearSessionCookie(w)

	// Redirect to Auth0 logout
	logoutURL := GenerateLogoutURL(h.config.Domain, h.config.ClientID, h.config.LogoutURL)
	http.Redirect(w, r, logoutURL, http.StatusTemporaryRedirect)
}

// HandleUserInfo handles the user info route
func (h *Handler) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	const op = "auth0_handle_user_info"

	// Get session from cookie
	session, err := h.sessionManager.GetSessionFromCookie(r)
	if err != nil {
		h.logger.Debug("no session found for user info", zap.String("op", op))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "not_authenticated",
			"message": "User is not authenticated",
		})
		return
	}

	// Prepare response
	response := map[string]interface{}{
		"authenticated": true,
		"user_id":       session.UserID,
		"profile":       session.Profile,
		"claims":        session.Claims,
		"session": map[string]interface{}{
			"id":         session.ID,
			"created_at": session.CreatedAt,
			"expires_at": session.ExpiresAt,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("failed to encode user info response", zap.String("op", op), zap.Error(err))
	}
}

// extractProfile extracts user profile information from claims
func (h *Handler) extractProfile(claims map[string]interface{}) map[string]interface{} {
	profile := make(map[string]interface{})

	// Standard OIDC claims
	profileFields := []string{
		"sub", "name", "given_name", "family_name", "middle_name",
		"nickname", "preferred_username", "profile", "picture",
		"website", "email", "email_verified", "gender", "birthdate",
		"zoneinfo", "locale", "phone_number", "phone_number_verified",
		"updated_at",
	}

	for _, field := range profileFields {
		if value, exists := claims[field]; exists {
			profile[field] = value
		}
	}

	// Auth0 specific claims
	auth0Fields := []string{
		"https://auth0.com/user_metadata",
		"https://auth0.com/app_metadata",
	}

	for _, field := range auth0Fields {
		if value, exists := claims[field]; exists {
			profile[field] = value
		}
	}

	return profile
}

// getRedirectURL determines where to redirect after successful authentication
func (h *Handler) getRedirectURL(r *http.Request) string {
	// Check for return_to parameter
	if returnTo := r.URL.Query().Get("return_to"); returnTo != "" {
		// Validate return_to URL to prevent open redirects
		if h.isValidReturnURL(returnTo) {
			return returnTo
		}
	}

	// Default redirect to root
	return "/"
}

// isValidReturnURL validates return URLs to prevent open redirects
func (h *Handler) isValidReturnURL(returnTo string) bool {
	// Parse the URL
	parsedURL, err := url.Parse(returnTo)
	if err != nil {
		return false
	}

	// Only allow relative URLs or same-origin URLs
	if parsedURL.IsAbs() {
		// For absolute URLs, must be same host
		if parsedURL.Host != "" {
			return false // For security, reject all absolute URLs with hosts
		}
	}

	// Reject javascript: and data: schemes
	if parsedURL.Scheme != "" && parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return false
	}

	// Must start with /
	if !strings.HasPrefix(returnTo, "/") {
		return false
	}

	// Reject URLs starting with //
	if strings.HasPrefix(returnTo, "//") {
		return false
	}

	return true
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code,omitempty"`
}

// writeErrorResponse writes a JSON error response
func (h *Handler) writeErrorResponse(w http.ResponseWriter, status int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := ErrorResponse{
		Error:   errorCode,
		Message: message,
		Code:    status,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.logger.Error("failed to encode error response", zap.Error(err))
	}
}
