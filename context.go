package auth0

// Auth0Data represents the complete Auth0 user data for PSR-7 attribute injection
// This structure is serialized to JSON and set as a single "auth0" attribute
type Auth0Data struct {
	UserID    string                 `json:"user_id"`
	SessionID string                 `json:"session_id"`
	Profile   map[string]interface{} `json:"profile"`
	Claims    map[string]interface{} `json:"claims"`
	Roles     []string               `json:"roles"`
}

// NewAuth0Data creates Auth0Data from a session
func NewAuth0Data(session *Session) *Auth0Data {
	if session == nil {
		return nil
	}

	return &Auth0Data{
		UserID:    session.UserID,
		SessionID: session.ID,
		Profile:   session.Profile,
		Claims:    session.Claims,
		Roles:     extractRoles(session.Claims),
	}
}

// extractRoles extracts roles from user claims
func extractRoles(claims map[string]interface{}) []string {
	if claims == nil {
		return nil
	}

	// Try common role claim names
	roleKeys := []string{
		"roles",
		"https://auth0.com/roles",
		"https://example.com/roles", // Custom namespace example
		"permissions",
		"https://auth0.com/permissions",
	}

	for _, key := range roleKeys {
		if roles := extractStringSlice(claims, key); len(roles) > 0 {
			return roles
		}
	}

	// Try extracting from app metadata
	if appMetadata, exists := claims["https://auth0.com/app_metadata"]; exists {
		if metadata, ok := appMetadata.(map[string]interface{}); ok {
			if roles := extractStringSlice(metadata, "roles"); len(roles) > 0 {
				return roles
			}
		}
	}

	return nil
}

// extractStringSlice extracts a string slice from a map
func extractStringSlice(data map[string]interface{}, key string) []string {
	value, exists := data[key]
	if !exists {
		return nil
	}

	switch v := value.(type) {
	case []string:
		return v
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	case string:
		// Single role as string
		return []string{v}
	default:
		return nil
	}
}
