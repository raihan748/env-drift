// Package security provides entropy analysis and placeholder leak detection.
// It detects common development placeholders, dummy credentials, and test keys
// inadvertently left in staging or production environment files.
package security

import (
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"
)

var (
	// Known dummy tokens and placeholder substrings.
	placeholderSubstrings = []string{
		"changeme",
		"change-me",
		"change_me",
		"password",
		"secret",
		"secret123",
		"admin",
		"placeholder",
		"your-api-key",
		"your_api_key",
		"your-token",
		"your-secret",
		"insert_here",
		"replace_me",
		"replace-me",
		"replace_with_actual",
		"dummy_key",
		"dummy-key",
		"dummy",
		"example",
		"sample",
		"test",
		"default",
		"todo",
		"xxx",
		"xxxxxx",
	}

	// Regex for mock provider tokens (e.g., dummy OpenAI, Stripe, GitHub).
	mockKeyPatterns = []*regexp.Regexp{
		regexp.MustCompile(`^sk-(?:proj-)?[xX0-9a-zA-Z]{15,}example`),
		regexp.MustCompile(`^ghp_[xX0-9a-zA-Z]{20,}dummy`),
		regexp.MustCompile(`^AKIA[0-9A-Z]{12}EXAMPLE$`),
	}
)

// LeakFinding details a security issue found in an environment variable.
type LeakFinding struct {
	Type        string
	Description string
	Remediation string
	Entropy     float64
}

// ShannonEntropy calculates the Shannon entropy in bits per character.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	freq := make(map[rune]float64)
	for _, char := range s {
		freq[char]++
	}
	total := float64(len([]rune(s)))
	var entropy float64
	for _, count := range freq {
		p := count / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// IsPlaceholder checks if a key-value pair represents a dummy or placeholder secret.
func IsPlaceholder(key, val string) (bool, string) {
	lowerVal := strings.ToLower(strings.TrimSpace(val))
	if lowerVal == "" {
		return false, ""
	}

	// Check exact matches or common placeholder substrings
	for _, sub := range placeholderSubstrings {
		if lowerVal == sub || (len(lowerVal) < 40 && strings.Contains(lowerVal, sub)) {
			return true, fmt.Sprintf("contains placeholder token %q", sub)
		}
	}

	// Check mock key regex patterns
	for _, pat := range mockKeyPatterns {
		if pat.MatchString(val) {
			return true, "matches synthetic test API key pattern"
		}
	}

	// For keys named explicitly with SECRET/KEY/PASSWORD/TOKEN/AUTH:
	upperKey := strings.ToUpper(key)
	if strings.Contains(upperKey, "SECRET") || strings.Contains(upperKey, "PASSWORD") ||
		strings.Contains(upperKey, "TOKEN") || strings.Contains(upperKey, "API_KEY") ||
		strings.Contains(upperKey, "AUTH") || strings.Contains(upperKey, "KEY") {
		// If length is very short (< 8) or trivial repeated chars
		if len(lowerVal) < 6 && (lowerVal == "test" || lowerVal == "pass" || lowerVal == "123456" || lowerVal == "root") {
			return true, fmt.Sprintf("trivial weak credential %q in sensitive key", lowerVal)
		}
	}

	return false, ""
}

// IsDevHost checks if a value references development endpoints (e.g. localhost, 127.0.0.1).
func IsDevHost(val string) (bool, string) {
	lowerVal := strings.ToLower(val)
	if strings.Contains(lowerVal, "localhost") {
		return true, "localhost"
	}
	if strings.Contains(lowerVal, "127.0.0.1") {
		return true, "127.0.0.1"
	}
	if strings.Contains(lowerVal, "0.0.0.0") {
		return true, "0.0.0.0"
	}
	return false, ""
}

// IsPlaintextHTTP checks if a value contains an unencrypted http:// URL.
func IsPlaintextHTTP(val string) bool {
	trimmed := strings.TrimSpace(val)
	if strings.HasPrefix(strings.ToLower(trimmed), "http://") {
		u, err := url.ParseRequestURI(trimmed)
		if err == nil && u.Scheme == "http" {
			// Ignore localhost in dev checks
			if u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
				return true
			}
		}
	}
	return false
}

// AnalyzeVariable performs a holistic security inspection of a key-value pair.
func AnalyzeVariable(key, val string, isProduction bool) *LeakFinding {
	entropy := ShannonEntropy(val)

	// 1. Placeholder check
	if isPlace, reason := IsPlaceholder(key, val); isPlace {
		return &LeakFinding{
			Type:        "PLACEHOLDER_LEAK",
			Description: fmt.Sprintf("Placeholder detected for %q: %s", key, reason),
			Remediation: "Replace dummy placeholder with genuine secure credential",
			Entropy:     entropy,
		}
	}

	// 2. Production specific checks
	if isProduction {
		if hasDev, host := IsDevHost(val); hasDev {
			return &LeakFinding{
				Type:        "DEV_HOST_IN_PROD",
				Description: fmt.Sprintf("Production key %q points to local development host (%s)", key, host),
				Remediation: "Configure production DNS hostname or cluster service endpoint",
				Entropy:     entropy,
			}
		}

		if IsPlaintextHTTP(val) {
			return &LeakFinding{
				Type:        "INSECURE_URL",
				Description: fmt.Sprintf("Production key %q uses unencrypted HTTP protocol", key),
				Remediation: "Migrate to HTTPS or TLS-encrypted endpoint",
				Entropy:     entropy,
			}
		}
	}

	return nil
}
