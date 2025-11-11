package auth0

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// SessionManager handles user sessions
type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	config   *SessionConfig
	secret   []byte
}

// Session represents a user session
type Session struct {
	ID        string                 `json:"id"`
	UserID    string                 `json:"user_id"`
	Profile   map[string]interface{} `json:"profile"`
	Claims    map[string]interface{} `json:"claims"`
	State     string                 `json:"state,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
	ExpiresAt time.Time              `json:"expires_at"`
}

// NewSessionManager creates a new session manager
func NewSessionManager(config *SessionConfig) *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
		config:   config,
		secret:   []byte(config.SecretKey),
	}
}

// CreateSession creates a new session
func (sm *SessionManager) CreateSession(userID string, profile, claims map[string]interface{}) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	now := time.Now()
	session := &Session{
		ID:        sessionID,
		UserID:    userID,
		Profile:   profile,
		Claims:    claims,
		CreatedAt: now,
		ExpiresAt: now.Add(sm.config.GetMaxAgeDuration()),
	}

	sm.sessions[sessionID] = session
	return session, nil
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(sessionID string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, false
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		// Clean up expired session
		go sm.DeleteSession(sessionID)
		return nil, false
	}

	return session, true
}

// UpdateSession updates an existing session
func (sm *SessionManager) UpdateSession(sessionID string, profile, claims map[string]interface{}) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found")
	}

	session.Profile = profile
	session.Claims = claims
	// Extend expiration
	session.ExpiresAt = time.Now().Add(sm.config.GetMaxAgeDuration())

	return nil
}

// DeleteSession removes a session
func (sm *SessionManager) DeleteSession(sessionID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	delete(sm.sessions, sessionID)
}

// CreateTempSession creates a temporary session for state storage during OAuth flow
func (sm *SessionManager) CreateTempSession(state string) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate temp session ID: %w", err)
	}

	now := time.Now()
	session := &Session{
		ID:        sessionID,
		State:     state,
		CreatedAt: now,
		ExpiresAt: now.Add(10 * time.Minute), // Short expiration for temp sessions
	}

	sm.sessions[sessionID] = session
	return session, nil
}

// ValidateState validates the OAuth state parameter
func (sm *SessionManager) ValidateState(sessionID, state string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[sessionID]
	if !exists {
		return false
	}

	return session.State == state
}

// SetSessionCookie sets the session cookie on the response
func (sm *SessionManager) SetSessionCookie(w http.ResponseWriter, session *Session) error {
	// Create signed cookie value
	cookieValue, err := sm.signValue(session.ID)
	if err != nil {
		return fmt.Errorf("failed to sign cookie value: %w", err)
	}

	cookie := &http.Cookie{
		Name:     sm.config.CookieName,
		Value:    cookieValue,
		Path:     "/",
		MaxAge:   sm.config.MaxAge,
		Secure:   sm.config.Secure,
		HttpOnly: sm.config.HTTPOnly,
		SameSite: sm.parseSameSite(sm.config.SameSite),
	}

	http.SetCookie(w, cookie)
	return nil
}

// GetSessionFromCookie extracts session ID from cookie and retrieves session
func (sm *SessionManager) GetSessionFromCookie(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie(sm.config.CookieName)
	if err != nil {
		return nil, fmt.Errorf("session cookie not found: %w", err)
	}

	// Verify and extract session ID
	sessionID, err := sm.verifyValue(cookie.Value)

	if err != nil {
		return nil, fmt.Errorf("invalid session cookie: %w", err)
	}

	session, exists := sm.GetSession(sessionID)
	if !exists {
		return nil, fmt.Errorf("session not found or expired")
	}

	return session, nil
}

// ClearSessionCookie clears the session cookie
func (sm *SessionManager) ClearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     sm.config.CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   sm.config.Secure,
		HttpOnly: sm.config.HTTPOnly,
		SameSite: sm.parseSameSite(sm.config.SameSite),
	}

	http.SetCookie(w, cookie)
}

// CleanupExpiredSessions removes expired sessions (should be called periodically)
func (sm *SessionManager) CleanupExpiredSessions() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	for id, session := range sm.sessions {
		if now.After(session.ExpiresAt) {
			delete(sm.sessions, id)
		}
	}
}

// GetSessionCount returns the number of active sessions
func (sm *SessionManager) GetSessionCount() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return len(sm.sessions)
}

// signValue creates a signed value using HMAC
func (sm *SessionManager) signValue(value string) (string, error) {
	mac := hmac.New(sha256.New, sm.secret)
	mac.Write([]byte(value))
	signature := mac.Sum(nil)

	data := map[string]string{
		"value":     value,
		"signature": base64.URLEncoding.EncodeToString(signature),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(jsonData), nil
}

// verifyValue verifies a signed value
func (sm *SessionManager) verifyValue(signedValue string) (string, error) {
	jsonData, err := base64.URLEncoding.DecodeString(signedValue)
	if err != nil {
		return "", fmt.Errorf("invalid base64 encoding: %w", err)
	}

	var data map[string]string
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return "", fmt.Errorf("invalid JSON data: %w", err)
	}

	value, ok := data["value"]
	if !ok {
		return "", fmt.Errorf("missing value field")
	}

	signature, ok := data["signature"]
	if !ok {
		return "", fmt.Errorf("missing signature field")
	}

	// Verify signature
	mac := hmac.New(sha256.New, sm.secret)
	mac.Write([]byte(value))
	expectedSignature := mac.Sum(nil)

	decodedSignature, err := base64.URLEncoding.DecodeString(signature)
	if err != nil {
		return "", fmt.Errorf("invalid signature encoding: %w", err)
	}

	if !hmac.Equal(decodedSignature, expectedSignature) {
		return "", fmt.Errorf("signature verification failed")
	}

	return value, nil
}

// parseSameSite converts string to http.SameSite
func (sm *SessionManager) parseSameSite(sameSite string) http.SameSite {
	switch sameSite {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	case "lax":
		fallthrough
	default:
		return http.SameSiteLaxMode
	}
}

// generateSessionID generates a cryptographically secure session ID
func generateSessionID() (string, error) {
	return GenerateState() // Reuse the state generation function
}
