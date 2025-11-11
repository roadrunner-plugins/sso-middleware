package auth0

// UserContext represents user information for PSR7 attribute injection
type UserContext struct {
	Authenticated bool                   `json:"authenticated"`
	UserID        string                 `json:"user_id,omitempty"`
	Profile       map[string]interface{} `json:"profile,omitempty"`
	Claims        map[string]interface{} `json:"claims,omitempty"`
	Roles         []string               `json:"roles,omitempty"`
	SessionID     string                 `json:"session_id,omitempty"`
}

// NewUserContext creates a UserContext from a session
func NewUserContext(session *Session) *UserContext {
	if session == nil {
		return &UserContext{
			Authenticated: false,
		}
	}

	return &UserContext{
		Authenticated: true,
		UserID:        session.UserID,
		Profile:       session.Profile,
		Claims:        session.Claims,
		Roles:         extractRoles(session.Claims),
		SessionID:     session.ID,
	}
}

// NewUnauthenticatedUserContext creates an unauthenticated UserContext
func NewUnauthenticatedUserContext() *UserContext {
	return &UserContext{
		Authenticated: false,
	}
}

// GetStringClaim gets a string claim from the user context
func (uc *UserContext) GetStringClaim(key string) (string, bool) {
	if uc.Claims == nil {
		return "", false
	}

	value, exists := uc.Claims[key]
	if !exists {
		return "", false
	}

	strValue, ok := value.(string)
	return strValue, ok
}

// GetStringSliceClaim gets a string slice claim from the user context
func (uc *UserContext) GetStringSliceClaim(key string) ([]string, bool) {
	if uc.Claims == nil {
		return nil, false
	}

	value, exists := uc.Claims[key]
	if !exists {
		return nil, false
	}

	switch v := value.(type) {
	case []string:
		return v, true
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result, len(result) > 0
	default:
		return nil, false
	}
}

// GetProfileString gets a string value from the user profile
func (uc *UserContext) GetProfileString(key string) (string, bool) {
	if uc.Profile == nil {
		return "", false
	}

	value, exists := uc.Profile[key]
	if !exists {
		return "", false
	}

	strValue, ok := value.(string)
	return strValue, ok
}

// GetEmail gets the user's email address
func (uc *UserContext) GetEmail() (string, bool) {
	return uc.GetProfileString("email")
}

// GetName gets the user's name
func (uc *UserContext) GetName() (string, bool) {
	return uc.GetProfileString("name")
}

// GetNickname gets the user's nickname
func (uc *UserContext) GetNickname() (string, bool) {
	return uc.GetProfileString("nickname")
}

// GetPicture gets the user's picture URL
func (uc *UserContext) GetPicture() (string, bool) {
	return uc.GetProfileString("picture")
}

// HasRole checks if the user has a specific role
func (uc *UserContext) HasRole(role string) bool {
	for _, userRole := range uc.Roles {
		if userRole == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if the user has any of the specified roles
func (uc *UserContext) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if uc.HasRole(role) {
			return true
		}
	}
	return false
}

// IsEmailVerified checks if the user's email is verified
func (uc *UserContext) IsEmailVerified() bool {
	if uc.Profile == nil {
		return false
	}

	verified, exists := uc.Profile["email_verified"]
	if !exists {
		return false
	}

	switch v := verified.(type) {
	case bool:
		return v
	case string:
		return v == "true"
	default:
		return false
	}
}

// GetMetadata gets user metadata (Auth0 specific)
func (uc *UserContext) GetMetadata(metadataType string) (map[string]interface{}, bool) {
	if uc.Claims == nil {
		return nil, false
	}

	key := "https://auth0.com/" + metadataType
	value, exists := uc.Claims[key]
	if !exists {
		return nil, false
	}

	metadata, ok := value.(map[string]interface{})
	return metadata, ok
}

// GetUserMetadata gets user metadata
func (uc *UserContext) GetUserMetadata() (map[string]interface{}, bool) {
	return uc.GetMetadata("user_metadata")
}

// GetAppMetadata gets app metadata
func (uc *UserContext) GetAppMetadata() (map[string]interface{}, bool) {
	return uc.GetMetadata("app_metadata")
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

// UserContextKey is the key used for user context in PSR7 attributes
const UserContextKey = "auth0_user_context"

// AttributeKeys holds the configuration for PSR7 attribute names
type AttributeKeys struct {
	Profile string
	Claims  string
	Roles   string
}

// NewAttributeKeys creates AttributeKeys from config
func NewAttributeKeys(config *UserAttributesConfig) *AttributeKeys {
	return &AttributeKeys{
		Profile: config.ProfileAttribute,
		Claims:  config.ClaimsAttribute,
		Roles:   config.RolesAttribute,
	}
}

// GetAttributeMap returns a map of attributes to inject into PSR7 request
func (uc *UserContext) GetAttributeMap(keys *AttributeKeys) map[string]interface{} {
	attributes := make(map[string]interface{})

	// Always include the full user context
	attributes[UserContextKey] = uc

	// Include individual attributes for backward compatibility
	if uc.Authenticated {
		attributes[keys.Profile] = uc.Profile
		attributes[keys.Claims] = uc.Claims
		attributes[keys.Roles] = uc.Roles
	} else {
		attributes[keys.Profile] = nil
		attributes[keys.Claims] = nil
		attributes[keys.Roles] = nil
	}

	return attributes
}
