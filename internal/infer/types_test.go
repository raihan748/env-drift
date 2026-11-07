package infer

import (
	"testing"
)

func TestInferType_TableDriven(t *testing.T) {
	tests := []struct {
		key      string
		val      string
		expected InferredType
	}{
		{"DEBUG", "true", TypeBoolean},
		{"ENABLE_METRICS", "false", TypeBoolean},
		{"IS_ADMIN", "1", TypeBoolean},
		{"PORT", "8080", TypePort},
		{"SERVER_PORT", "3000", TypePort},
		{"MAX_RETRIES", "5", TypeInteger},
		{"TIMEOUT_SECONDS", "30", TypeInteger},
		{"RATIO", "0.75", TypeFloat},
		{"RATE_LIMIT", "-1.5", TypeFloat},
		{"CACHE_TTL", "15m", TypeDuration},
		{"CONNECT_TIMEOUT", "500ms", TypeDuration},
		{"SESSION_ID", "c9a646d3-9c61-4cd9-bc19-470a7224e7aa", TypeUUID},
		{"ADMIN_EMAIL", "developer@smktelkom-mks.sch.id", TypeEmail},
		{"API_URL", "https://api.example.com/v1", TypeURL},
		{"DATABASE_URL", "postgres://user:pass@localhost:5432/dbname", TypeURL},
		{"REDIS_URL", "redis://cache.internal:6379", TypeURL},
		{"CONFIG_JSON", `{"service":"auth","active":true}`, TypeJSON},
		{"API_SECRET", "super-secret-production-token-xyz123", TypeSecret},
		{"APP_GREETING", "Hello World!", TypeString},
	}

	for _, tc := range tests {
		got := InferType(tc.key, tc.val)
		if got != tc.expected {
			t.Errorf("InferType(%q, %q) = %s; want %s", tc.key, tc.val, got, tc.expected)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	lowEntropy := ShannonEntropy("aaaaaaaaaaaa")
	highEntropy := ShannonEntropy("aB7#x9$L2!mK0@pQ")

	if lowEntropy > 1.0 {
		t.Errorf("expected low entropy for repeated chars, got %f", lowEntropy)
	}
	if highEntropy < 3.5 {
		t.Errorf("expected high entropy for random string, got %f", highEntropy)
	}
}
