// Package infer provides a heuristic data type inference engine for .env values.
// It detects integers, ports, booleans, URLs, emails, UUIDs, durations, JSON,
// secrets (via Shannon entropy and naming heuristics), and standard strings.
package infer

import (
	"encoding/json"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// InferredType represents the classified data type of an environment variable.
type InferredType string

const (
	TypeInteger  InferredType = "INTEGER"
	TypeFloat    InferredType = "FLOAT"
	TypeBoolean  InferredType = "BOOLEAN"
	TypeURL      InferredType = "URL"
	TypeEmail    InferredType = "EMAIL"
	TypePort     InferredType = "PORT"
	TypeUUID     InferredType = "UUID"
	TypeJSON     InferredType = "JSON"
	TypeDuration InferredType = "DURATION"
	TypeSecret   InferredType = "SECRET"
	TypeString   InferredType = "STRING"
)

var (
	emailRegex    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	uuidRegex     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	durationRegex = regexp.MustCompile(`^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$`)
	secretKeyRegex = regexp.MustCompile(`(?i)(KEY|SECRET|TOKEN|PASSWORD|PASS|AUTH|PRIVATE|CREDENTIAL|SIGNATURE|SALT|APIKEY|API_KEY)`)
)

// ShannonEntropy calculates the bits of information per character for string s.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	freq := make(map[rune]float64)
	for _, char := range s {
		freq[char]++
	}

	length := float64(len([]rune(s)))
	var entropy float64

	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// InferType analyzes a key-value pair and infers its semantic InferredType.
func InferType(key, val string) InferredType {
	trimmedVal := strings.TrimSpace(val)
	if trimmedVal == "" {
		return TypeString
	}

	upperKey := strings.ToUpper(key)
	lowerVal := strings.ToLower(trimmedVal)

	// 1. Boolean check (common representations)
	switch lowerVal {
	case "true", "false", "yes", "no", "on", "off":
		return TypeBoolean
	case "1", "0":
		if strings.HasPrefix(upperKey, "IS_") ||
			strings.HasPrefix(upperKey, "ENABLE_") ||
			strings.HasPrefix(upperKey, "DEBUG") ||
			strings.HasPrefix(upperKey, "ACTIVE") ||
			strings.HasSuffix(upperKey, "_FLAG") ||
			strings.HasSuffix(upperKey, "_ENABLED") {
			return TypeBoolean
		}
	}

	// 2. Port check (must precede generic Integer)
	if intVal, err := strconv.Atoi(trimmedVal); err == nil {
		if intVal >= 1 && intVal <= 65535 && strings.Contains(upperKey, "PORT") {
			return TypePort
		}
		return TypeInteger
	}

	// 3. Float check
	if _, err := strconv.ParseFloat(trimmedVal, 64); err == nil && strings.Contains(trimmedVal, ".") {
		return TypeFloat
	}

	// 4. Duration check (e.g. 10s, 5m, 24h, 500ms)
	if durationRegex.MatchString(trimmedVal) {
		if _, err := time.ParseDuration(trimmedVal); err == nil {
			return TypeDuration
		}
	}

	// 5. UUID check (RFC 4122)
	if uuidRegex.MatchString(trimmedVal) {
		return TypeUUID
	}

	// 6. Email check
	if emailRegex.MatchString(trimmedVal) {
		return TypeEmail
	}

	// 7. URL check (supports http, https, postgres, redis, grpc, etc.)
	if isURL(trimmedVal) {
		return TypeURL
	}

	// 8. JSON check
	if (strings.HasPrefix(trimmedVal, "{") && strings.HasSuffix(trimmedVal, "}")) ||
		(strings.HasPrefix(trimmedVal, "[") && strings.HasSuffix(trimmedVal, "]")) {
		if json.Valid([]byte(trimmedVal)) {
			return TypeJSON
		}
	}

	// 9. Secret check (entropy or sensitive key naming)
	entropy := ShannonEntropy(trimmedVal)
	if (len(trimmedVal) >= 16 && entropy > 3.8) || (secretKeyRegex.MatchString(key) && len(trimmedVal) >= 8) {
		return TypeSecret
	}

	// 10. Default fallback
	return TypeString
}

// isURL checks if s represents a valid URI with a scheme and host.
func isURL(s string) bool {
	u, err := url.ParseRequestURI(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	validSchemes := map[string]bool{
		"http":       true,
		"https":      true,
		"postgres":   true,
		"postgresql": true,
		"redis":      true,
		"rediss":     true,
		"mysql":      true,
		"mongodb":    true,
		"amqp":       true,
		"amqps":      true,
		"grpc":       true,
		"ws":         true,
		"wss":        true,
		"ftp":        true,
		"ftps":       true,
	}
	return validSchemes[strings.ToLower(u.Scheme)]
}

// AreTypesCompatible checks if two inferred types can be considered compatible.
func AreTypesCompatible(t1, t2 InferredType) bool {
	if t1 == t2 {
		return true
	}
	// Integer and Port are inter-compatible
	if (t1 == TypeInteger && t2 == TypePort) || (t1 == TypePort && t2 == TypeInteger) {
		return true
	}
	// Secret and String have high overlap
	if (t1 == TypeSecret && t2 == TypeString) || (t1 == TypeString && t2 == TypeSecret) {
		return true
	}
	// Float and Integer can be compatible in loose environments
	if (t1 == TypeFloat && t2 == TypeInteger) || (t1 == TypeInteger && t2 == TypeFloat) {
		return true
	}
	return false
}
