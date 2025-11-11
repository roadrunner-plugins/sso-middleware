package auth0

import (
	"encoding/json"
	"time"
)

// RPC provides external API access to the Auth0 middleware
type RPC struct {
	plugin *Plugin
}

// GetSessionInfo returns information about a user session
type GetSessionInfoRequest struct {
	SessionID string `json:"session_id"`
}

type GetSessionInfoResponse struct {
	Found     bool                   `json:"found"`
	UserID    string                 `json:"user_id,omitempty"`
	Profile   map[string]interface{} `json:"profile,omitempty"`
	Claims    map[string]interface{} `json:"claims,omitempty"`
	CreatedAt *time.Time             `json:"created_at,omitempty"`
	ExpiresAt *time.Time             `json:"expires_at,omitempty"`
}

// GetStats returns middleware statistics
type GetStatsResponse struct {
	ActiveSessions   int               `json:"active_sessions"`
	ProtectionMode   string            `json:"protection_mode"`
	PatternStats     PatternStats      `json:"pattern_stats"`
	Domain           string            `json:"domain"`
	ConfiguredRoutes map[string]string `json:"configured_routes"`
}

// InvalidateSession invalidates a user session
type InvalidateSessionRequest struct {
	SessionID string `json:"session_id,omitempty"`
	UserID    string `json:"user_id,omitempty"`
}

type InvalidateSessionResponse struct {
	Success         bool `json:"success"`
	SessionsRemoved int  `json:"sessions_removed"`
}

// ValidateToken validates a user session and returns user info
type ValidateTokenRequest struct {
	SessionID string `json:"session_id"`
}

type ValidateTokenResponse struct {
	Valid     bool                   `json:"valid"`
	UserID    string                 `json:"user_id,omitempty"`
	Profile   map[string]interface{} `json:"profile,omitempty"`
	Claims    map[string]interface{} `json:"claims,omitempty"`
	ExpiresAt *time.Time             `json:"expires_at,omitempty"`
}

// GetSessionInfo retrieves information about a specific session
func (rpc *RPC) GetSessionInfo(req *GetSessionInfoRequest, resp *GetSessionInfoResponse) error {
	if req.SessionID == "" {
		resp.Found = false
		return nil
	}

	session, found := rpc.plugin.sessionManager.GetSession(req.SessionID)
	if !found {
		resp.Found = false
		return nil
	}

	resp.Found = true
	resp.UserID = session.UserID
	resp.Profile = session.Profile
	resp.Claims = session.Claims
	resp.CreatedAt = &session.CreatedAt
	resp.ExpiresAt = &session.ExpiresAt

	return nil
}

// GetStats returns middleware statistics and configuration
func (rpc *RPC) GetStats(_ *struct{}, resp *GetStatsResponse) error {
	resp.ActiveSessions = rpc.plugin.sessionManager.GetSessionCount()
	resp.ProtectionMode = rpc.plugin.config.Protection.Mode
	resp.PatternStats = rpc.plugin.urlMatcher.GetPatternStats()
	resp.Domain = rpc.plugin.config.Domain
	resp.ConfiguredRoutes = map[string]string{
		"login":     rpc.plugin.config.Routes.Login,
		"callback":  rpc.plugin.config.Routes.Callback,
		"logout":    rpc.plugin.config.Routes.Logout,
		"user_info": rpc.plugin.config.Routes.UserInfo,
	}

	return nil
}

// InvalidateSession invalidates one or more sessions
func (rpc *RPC) InvalidateSession(req *InvalidateSessionRequest, resp *InvalidateSessionResponse) error {
	removed := 0

	if req.SessionID != "" {
		// Invalidate specific session
		_, found := rpc.plugin.sessionManager.GetSession(req.SessionID)
		if found {
			rpc.plugin.sessionManager.DeleteSession(req.SessionID)
			removed = 1
		}
	} else if req.UserID != "" {
		// Invalidate all sessions for a user
		removed = rpc.invalidateUserSessions(req.UserID)
	}

	resp.Success = removed > 0
	resp.SessionsRemoved = removed

	return nil
}

// ValidateToken validates a session token and returns user information
func (rpc *RPC) ValidateToken(req *ValidateTokenRequest, resp *ValidateTokenResponse) error {
	if req.SessionID == "" {
		resp.Valid = false
		return nil
	}

	session, found := rpc.plugin.sessionManager.GetSession(req.SessionID)
	if !found {
		resp.Valid = false
		return nil
	}

	resp.Valid = true
	resp.UserID = session.UserID
	resp.Profile = session.Profile
	resp.Claims = session.Claims
	resp.ExpiresAt = &session.ExpiresAt

	return nil
}

// CleanupSessions forces cleanup of expired sessions
func (rpc *RPC) CleanupSessions(_ *struct{}, resp *struct{ Cleaned bool }) error {
	rpc.plugin.sessionManager.CleanupExpiredSessions()
	resp.Cleaned = true
	return nil
}

// GetUserSessions returns all sessions for a specific user
type GetUserSessionsRequest struct {
	UserID string `json:"user_id"`
}

type GetUserSessionsResponse struct {
	Sessions []SessionInfo `json:"sessions"`
}

type SessionInfo struct {
	ID        string                 `json:"id"`
	CreatedAt time.Time              `json:"created_at"`
	ExpiresAt time.Time              `json:"expires_at"`
	Profile   map[string]interface{} `json:"profile"`
}

// GetUserSessions retrieves all active sessions for a user
func (rpc *RPC) GetUserSessions(req *GetUserSessionsRequest, resp *GetUserSessionsResponse) error {
	if req.UserID == "" {
		resp.Sessions = []SessionInfo{}
		return nil
	}

	sessions := rpc.getUserSessions(req.UserID)
	resp.Sessions = sessions

	return nil
}

// TestProtection tests URL protection rules
type TestProtectionRequest struct {
	URL string `json:"url"`
}

type TestProtectionResponse struct {
	Protected bool   `json:"protected"`
	Reason    string `json:"reason"`
	Pattern   string `json:"pattern,omitempty"`
}

// TestProtection tests whether a URL would be protected
func (rpc *RPC) TestProtection(req *TestProtectionRequest, resp *TestProtectionResponse) error {
	if req.URL == "" {
		resp.Protected = false
		resp.Reason = "empty_url"
		return nil
	}

	result := rpc.plugin.urlMatcher.ShouldProtect(req.URL)
	resp.Protected = result.Protected
	resp.Reason = result.Reason
	resp.Pattern = result.Pattern

	return nil
}

// GetConfig returns sanitized configuration (without secrets)
type GetConfigResponse struct {
	Domain        string           `json:"domain"`
	CallbackURL   string           `json:"callback_url"`
	LogoutURL     string           `json:"logout_url"`
	Protection    ProtectionConfig `json:"protection"`
	Routes        RoutesConfig     `json:"routes"`
	Scopes        []string         `json:"scopes"`
	SessionMaxAge int              `json:"session_max_age"`
}

// GetConfig returns sanitized configuration
func (rpc *RPC) GetConfig(_ *struct{}, resp *GetConfigResponse) error {
	resp.Domain = rpc.plugin.config.Domain
	resp.CallbackURL = rpc.plugin.config.CallbackURL
	resp.LogoutURL = rpc.plugin.config.LogoutURL
	resp.Protection = rpc.plugin.config.Protection
	resp.Routes = rpc.plugin.config.Routes
	resp.Scopes = rpc.plugin.config.Scopes
	resp.SessionMaxAge = rpc.plugin.config.Session.MaxAge

	return nil
}

// Helper methods

// invalidateUserSessions invalidates all sessions for a specific user
func (rpc *RPC) invalidateUserSessions(userID string) int {
	// This is a simplified implementation
	// In a real scenario, you'd want to iterate through sessions more efficiently
	sessions := rpc.getUserSessions(userID)

	for _, session := range sessions {
		rpc.plugin.sessionManager.DeleteSession(session.ID)
	}

	return len(sessions)
}

// getUserSessions returns all sessions for a specific user
func (rpc *RPC) getUserSessions(userID string) []SessionInfo {
	// Note: This is a basic implementation that iterates through all sessions
	// For production use with many sessions, consider indexing sessions by user ID
	var userSessions []SessionInfo

	// We need to access the internal session map
	// This is a simplified approach - in production you might want a more efficient lookup
	rpc.plugin.sessionManager.mu.RLock()
	defer rpc.plugin.sessionManager.mu.RUnlock()

	for _, session := range rpc.plugin.sessionManager.sessions {
		if session.UserID == userID {
			userSessions = append(userSessions, SessionInfo{
				ID:        session.ID,
				CreatedAt: session.CreatedAt,
				ExpiresAt: session.ExpiresAt,
				Profile:   session.Profile,
			})
		}
	}

	return userSessions
}

// JsonString returns a JSON string representation of any response
func (rpc *RPC) JsonString(data interface{}) (string, error) {
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
