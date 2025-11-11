package auth0

import (
	"regexp"
	"strings"
)

// URLMatcher handles URL pattern matching for authentication
type URLMatcher struct {
	protectedPatterns []*regexp.Regexp
	excludedPatterns  []*regexp.Regexp
	publicRoutes      map[string]bool
	mode              string
}

// NewURLMatcher creates a new URL matcher
func NewURLMatcher(config *ProtectionConfig) (*URLMatcher, error) {
	matcher := &URLMatcher{
		publicRoutes: make(map[string]bool),
		mode:         config.Mode,
	}

	// Compile protected patterns
	for _, pattern := range config.ProtectedPatterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, &MatcherError{
				Pattern: pattern,
				Type:    "protected",
				Err:     err,
			}
		}
		matcher.protectedPatterns = append(matcher.protectedPatterns, regex)
	}

	// Compile excluded patterns
	for _, pattern := range config.ExcludedPatterns {
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return nil, &MatcherError{
				Pattern: pattern,
				Type:    "excluded",
				Err:     err,
			}
		}
		matcher.excludedPatterns = append(matcher.excludedPatterns, regex)
	}

	// Store public routes
	for _, route := range config.PublicRoutes {
		matcher.publicRoutes[route] = true
	}

	return matcher, nil
}

// ShouldProtect determines if a URL should be protected
func (m *URLMatcher) ShouldProtect(path string) ProtectionResult {
	// Normalize path
	path = m.normalizePath(path)

	// First check excluded patterns - they override everything
	if m.matchesExcludedPatterns(path) {
		return ProtectionResult{
			Protected: false,
			Reason:    "excluded_pattern",
			Pattern:   m.getMatchingExcludedPattern(path),
		}
	}

	switch m.mode {
	case "disabled":
		return ProtectionResult{
			Protected: false,
			Reason:    "disabled",
		}

	case "global":
		// Global mode protects everything except public routes
		if m.isPublicRoute(path) {
			return ProtectionResult{
				Protected: false,
				Reason:    "public_route",
			}
		}
		return ProtectionResult{
			Protected: true,
			Reason:    "global_protection",
		}

	case "pattern":
		// Pattern mode only protects URLs matching protected patterns
		if m.isPublicRoute(path) {
			return ProtectionResult{
				Protected: false,
				Reason:    "public_route",
			}
		}

		if m.matchesProtectedPatterns(path) {
			return ProtectionResult{
				Protected: true,
				Reason:    "protected_pattern",
				Pattern:   m.getMatchingProtectedPattern(path),
			}
		}

		return ProtectionResult{
			Protected: false,
			Reason:    "no_pattern_match",
		}

	default:
		// Unknown mode, default to no protection
		return ProtectionResult{
			Protected: false,
			Reason:    "unknown_mode",
		}
	}
}

// IsAuthRoute checks if the path is an authentication route
func (m *URLMatcher) IsAuthRoute(path, authPath string) bool {
	return m.normalizePath(path) == m.normalizePath(authPath)
}

// matchesProtectedPatterns checks if path matches any protected pattern
func (m *URLMatcher) matchesProtectedPatterns(path string) bool {
	for _, pattern := range m.protectedPatterns {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

// matchesExcludedPatterns checks if path matches any excluded pattern
func (m *URLMatcher) matchesExcludedPatterns(path string) bool {
	for _, pattern := range m.excludedPatterns {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

// isPublicRoute checks if path is a public route
func (m *URLMatcher) isPublicRoute(path string) bool {
	return m.publicRoutes[path]
}

// getMatchingProtectedPattern returns the first matching protected pattern
func (m *URLMatcher) getMatchingProtectedPattern(path string) string {
	for _, pattern := range m.protectedPatterns {
		if pattern.MatchString(path) {
			// Find the original pattern string by index
			return pattern.String()
		}
	}
	return ""
}

// getMatchingExcludedPattern returns the first matching excluded pattern
func (m *URLMatcher) getMatchingExcludedPattern(path string) string {
	for _, pattern := range m.excludedPatterns {
		if pattern.MatchString(path) {
			return pattern.String()
		}
	}
	return ""
}

// normalizePath normalizes URL path for consistent matching
func (m *URLMatcher) normalizePath(path string) string {
	// Remove query parameters
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}

	// Remove fragment
	if idx := strings.Index(path, "#"); idx != -1 {
		path = path[:idx]
	}

	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// Remove trailing slash (except for root)
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = path[:len(path)-1]
	}

	return path
}

// ProtectionResult represents the result of URL protection evaluation
type ProtectionResult struct {
	Protected bool   `json:"protected"`
	Reason    string `json:"reason"`
	Pattern   string `json:"pattern,omitempty"`
}

// String returns a string representation of the protection result
func (pr *ProtectionResult) String() string {
	if pr.Pattern != "" {
		return pr.Reason + " (" + pr.Pattern + ")"
	}
	return pr.Reason
}

// MatcherError represents URL pattern matching errors
type MatcherError struct {
	Pattern string
	Type    string
	Err     error
}

func (e *MatcherError) Error() string {
	return "invalid " + e.Type + " pattern '" + e.Pattern + "': " + e.Err.Error()
}

func (e *MatcherError) Unwrap() error {
	return e.Err
}

// ValidatePatterns validates regex patterns without creating a matcher
func ValidatePatterns(patterns []string) error {
	for _, pattern := range patterns {
		_, err := regexp.Compile(pattern)
		if err != nil {
			return &MatcherError{
				Pattern: pattern,
				Type:    "validation",
				Err:     err,
			}
		}
	}
	return nil
}

// GetPatternStats returns statistics about pattern matching
func (m *URLMatcher) GetPatternStats() PatternStats {
	return PatternStats{
		Mode:              m.mode,
		ProtectedPatterns: len(m.protectedPatterns),
		ExcludedPatterns:  len(m.excludedPatterns),
		PublicRoutes:      len(m.publicRoutes),
	}
}

// PatternStats represents pattern matching statistics
type PatternStats struct {
	Mode              string `json:"mode"`
	ProtectedPatterns int    `json:"protected_patterns"`
	ExcludedPatterns  int    `json:"excluded_patterns"`
	PublicRoutes      int    `json:"public_routes"`
}
