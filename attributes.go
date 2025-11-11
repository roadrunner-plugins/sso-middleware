package auth0

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	rrcontext "github.com/roadrunner-server/context"
)

// AttributesHelper provides a wrapper around the PSR attributes system
// specifically for Auth0 middleware integration
type AttributesHelper struct{}

// NewAttributesHelper creates a new attributes helper
func NewAttributesHelper() *AttributesHelper {
	return &AttributesHelper{}
}

type attrs map[string][]string

func (v attrs) get(key string) any {
	if v == nil {
		return ""
	}
	return v[key]
}

func (v attrs) set(key string, value string) {
	if v[key] == nil {
		v[key] = []string{value}
		return
	}
	v[key] = append(v[key], value)
}

func (v attrs) del(key string) {
	delete(v, key)
}

// Init initializes PSR attributes for the request if not already initialized
func (ah *AttributesHelper) Init(r *http.Request) *http.Request {
	// Do not overwrite existing PSR attributes
	if val := r.Context().Value(rrcontext.PsrContextKey); val == nil {
		return r.WithContext(context.WithValue(r.Context(), rrcontext.PsrContextKey, attrs{}))
	}
	return r
}

// Set sets a string value in PSR attributes
func (ah *AttributesHelper) Set(r *http.Request, key string, value string) error {
	v := r.Context().Value(rrcontext.PsrContextKey)
	if v == nil {
		return errors.New("unable to find `psr:attributes` context key")
	}

	v.(attrs).set(key, value)
	return nil
}

// Get retrieves a value from PSR attributes
func (ah *AttributesHelper) Get(r *http.Request, key string) any {
	v := r.Context().Value(rrcontext.PsrContextKey)
	if v == nil {
		return nil
	}
	return v.(attrs).get(key)
}

// GetString retrieves a string value from PSR attributes
func (ah *AttributesHelper) GetString(r *http.Request, key string) string {
	val := ah.Get(r, key)
	if val == nil {
		return ""
	}

	switch v := val.(type) {
	case string:
		return v
	case []string:
		if len(v) > 0 {
			return v[0]
		}
		return ""
	default:
		return ""
	}
}

// GetBool retrieves a boolean value from PSR attributes
func (ah *AttributesHelper) GetBool(r *http.Request, key string) bool {
	val := ah.GetString(r, key)
	if val == "" {
		return false
	}

	result, err := strconv.ParseBool(val)
	if err != nil {
		return false
	}
	return result
}

// GetUserContext retrieves and deserializes the Auth0 user context
func (ah *AttributesHelper) GetUserContext(r *http.Request) (*UserContext, error) {
	contextJSON := ah.GetString(r, UserContextKey)
	if contextJSON == "" {
		return NewUnauthenticatedUserContext(), nil
	}

	var userContext UserContext
	if err := json.Unmarshal([]byte(contextJSON), &userContext); err != nil {
		return nil, err
	}

	return &userContext, nil
}

// GetUserProfile retrieves and deserializes the user profile
func (ah *AttributesHelper) GetUserProfile(r *http.Request, profileKey string) (map[string]interface{}, error) {
	profileJSON := ah.GetString(r, profileKey)
	if profileJSON == "" || profileJSON == "null" {
		return nil, nil
	}

	var profile map[string]interface{}
	if err := json.Unmarshal([]byte(profileJSON), &profile); err != nil {
		return nil, err
	}

	return profile, nil
}

// GetUserClaims retrieves and deserializes the user claims
func (ah *AttributesHelper) GetUserClaims(r *http.Request, claimsKey string) (map[string]interface{}, error) {
	claimsJSON := ah.GetString(r, claimsKey)
	if claimsJSON == "" || claimsJSON == "null" {
		return nil, nil
	}

	var claims map[string]interface{}
	if err := json.Unmarshal([]byte(claimsJSON), &claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// GetUserRoles retrieves and deserializes the user roles
func (ah *AttributesHelper) GetUserRoles(r *http.Request, rolesKey string) ([]string, error) {
	rolesJSON := ah.GetString(r, rolesKey)
	if rolesJSON == "" || rolesJSON == "[]" {
		return []string{}, nil
	}

	var roles []string
	if err := json.Unmarshal([]byte(rolesJSON), &roles); err != nil {
		return nil, err
	}

	return roles, nil
}

// IsAuthenticated checks if the current request is authenticated
func (ah *AttributesHelper) IsAuthenticated(r *http.Request) bool {
	return ah.GetBool(r, "auth0_authenticated")
}

// GetUserID retrieves the authenticated user's ID
func (ah *AttributesHelper) GetUserID(r *http.Request) string {
	return ah.GetString(r, "auth0_user_id")
}

// GetSessionID retrieves the current session ID
func (ah *AttributesHelper) GetSessionID(r *http.Request) string {
	return ah.GetString(r, "auth0_session_id")
}

// GetEmail retrieves the user's email address
func (ah *AttributesHelper) GetEmail(r *http.Request) string {
	return ah.GetString(r, "auth0_email")
}

// GetName retrieves the user's name
func (ah *AttributesHelper) GetName(r *http.Request) string {
	return ah.GetString(r, "auth0_name")
}

// GetNickname retrieves the user's nickname
func (ah *AttributesHelper) GetNickname(r *http.Request) string {
	return ah.GetString(r, "auth0_nickname")
}

// GetPicture retrieves the user's picture URL
func (ah *AttributesHelper) GetPicture(r *http.Request) string {
	return ah.GetString(r, "auth0_picture")
}

// IsEmailVerified checks if the user's email is verified
func (ah *AttributesHelper) IsEmailVerified(r *http.Request) bool {
	return ah.GetBool(r, "auth0_email_verified")
}

// HasRole checks if the user has a specific role (by checking individual role attributes)
func (ah *AttributesHelper) HasRole(r *http.Request, role string) bool {
	// First try to get roles from JSON array
	if rolesKey := ah.GetString(r, "auth0_roles"); rolesKey != "" {
		if roles, err := ah.GetUserRoles(r, "auth0_roles"); err == nil {
			for _, userRole := range roles {
				if userRole == role {
					return true
				}
			}
		}
	}

	// Also check individual role attributes (auth0_role_0, auth0_role_1, etc.)
	for i := 0; i < 10; i++ { // Check first 10 roles
		roleKey := "auth0_role_" + strconv.Itoa(i)
		if ah.GetString(r, roleKey) == role {
			return true
		}
	}

	return false
}

// All returns all PSR attributes
func (ah *AttributesHelper) All(r *http.Request) map[string][]string {
	v := r.Context().Value(rrcontext.PsrContextKey)
	if v == nil {
		return nil
	}

	switch t := v.(type) {
	case attrs:
		return t
	case map[string][]string:
		return t
	case map[string]string:
		newm := make(map[string][]string)
		for k, v := range t {
			newm[k] = []string{v}
		}
		return newm
	default:
		return nil
	}
}

// Delete removes an attribute
func (ah *AttributesHelper) Delete(r *http.Request, key string) {
	v := r.Context().Value(rrcontext.PsrContextKey)
	if v == nil {
		return
	}

	v.(attrs).del(key)
}
