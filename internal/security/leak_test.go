package security

import (
	"testing"
)

func TestLeak_PlaceholderDetection(t *testing.T) {
	placeholders := []struct {
		key string
		val string
	}{
		{"JWT_SECRET", "changeme"},
		{"DB_PASSWORD", "secret123"},
		{"API_TOKEN", "your-api-key"},
		{"ADMIN_PASS", "password"},
		{"TODO_ITEM", "todo"},
		{"AWS_KEY", "AKIA123456789012EXAMPLE"},
		{"OPENAI_KEY", "sk-proj-1234567890123456789example"},
		{"AUTH_KEY", "test"},
	}

	for _, tc := range placeholders {
		isPlace, reason := IsPlaceholder(tc.key, tc.val)
		if !isPlace {
			t.Errorf("expected %q (%s) to be detected as placeholder, reason: %s", tc.val, tc.key, reason)
		}
	}

	validKeys := []struct {
		key string
		val string
	}{
		{"JWT_SECRET", "nB8#vR2$mK9!qW5@zT7&xP4*"},
		{"DATABASE_URL", "postgres://user:pass@db.internal:5432/main"},
		{"ADMIN_EMAIL", "security@smktelkom-mks.sch.id"},
	}

	for _, tc := range validKeys {
		isPlace, _ := IsPlaceholder(tc.key, tc.val)
		if isPlace {
			t.Errorf("expected %q (%s) to NOT be flagged as placeholder", tc.val, tc.key)
		}
	}
}

func TestLeak_DevHostDetection(t *testing.T) {
	cases := []struct {
		input    string
		expected bool
	}{
		{"http://localhost:8080", true},
		{"postgres://user:pass@127.0.0.1:5432/db", true},
		{"http://0.0.0.0:3000", true},
		{"https://api.smktelkom-mks.sch.id", false},
		{"postgres://db.cluster.aws.internal:5432/live", false},
	}

	for _, tc := range cases {
		got, _ := IsDevHost(tc.input)
		if got != tc.expected {
			t.Errorf("IsDevHost(%q) = %v, want %v", tc.input, got, tc.expected)
		}
	}
}

func TestLeak_PlaintextHTTP(t *testing.T) {
	if !IsPlaintextHTTP("http://insecure-api.domain.com/v1") {
		t.Errorf("expected plaintext HTTP URL to be flagged")
	}
	if IsPlaintextHTTP("https://secure-api.domain.com/v1") {
		t.Errorf("expected HTTPS URL to not be flagged")
	}
}

func TestLeak_AnalyzeVariableProduction(t *testing.T) {
	// 1. Placeholder in production -> CRITICAL
	finding1 := AnalyzeVariable("API_KEY", "changeme", true)
	if finding1 == nil || finding1.Type != "PLACEHOLDER_LEAK" {
		t.Fatalf("expected PLACEHOLDER_LEAK, got %v", finding1)
	}

	// 2. Localhost in production -> DEV_HOST_IN_PROD
	finding2 := AnalyzeVariable("BASE_URL", "http://localhost:3000", true)
	if finding2 == nil || finding2.Type != "DEV_HOST_IN_PROD" {
		t.Fatalf("expected DEV_HOST_IN_PROD, got %v", finding2)
	}

	// 3. Insecure URL in production -> INSECURE_URL
	finding3 := AnalyzeVariable("METRICS_URL", "http://metrics.internal.com/data", true)
	if finding3 == nil || finding3.Type != "INSECURE_URL" {
		t.Fatalf("expected INSECURE_URL, got %v", finding3)
	}

	// 4. Clean production variable -> nil
	finding4 := AnalyzeVariable("API_SECRET", "k9!mX7#pQ2@vR4$wT1*zA6", true)
	if finding4 != nil {
		t.Fatalf("expected clean variable to yield nil finding, got %v", finding4)
	}
}
