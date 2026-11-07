package analyzer

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/smktelkom-dev/env-drift/internal/parser"
)

func TestAnalyzer_DriftDetectionWithTestdata(t *testing.T) {
	testdataDir := filepath.Join("..", "..", "testdata")

	baseFile, err := parser.ParseFile(filepath.Join(testdataDir, ".env.example"))
	if err != nil {
		t.Fatalf("failed to parse .env.example: %v", err)
	}

	prodFile, err := parser.ParseFile(filepath.Join(testdataDir, ".env.production"))
	if err != nil {
		t.Fatalf("failed to parse .env.production: %v", err)
	}

	report, err := Analyze(baseFile, []*parser.EnvFile{prodFile}, false)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if report.Passed {
		t.Errorf("expected report.Passed to be false due to critical issues in .env.production")
	}

	var foundMissingAllowedOrigins, foundPlaceholderJWT, foundInsecurePayment, foundTypeMismatchPort bool

	for _, issue := range report.Issues {
		if issue.Key == "ALLOWED_ORIGINS" && issue.IssueType == "MISSING_KEY" {
			foundMissingAllowedOrigins = true
		}
		if issue.Key == "JWT_SECRET" && issue.IssueType == "PLACEHOLDER_LEAK" {
			foundPlaceholderJWT = true
		}
		if issue.Key == "PAYMENT_GATEWAY_URL" && issue.IssueType == "INSECURE_URL" {
			foundInsecurePayment = true
		}
		if issue.Key == "METRICS_PORT" && issue.IssueType == "TYPE_MISMATCH" {
			foundTypeMismatchPort = true
		}
	}

	if !foundMissingAllowedOrigins {
		t.Errorf("expected to find MISSING_KEY issue for ALLOWED_ORIGINS")
	}
	if !foundPlaceholderJWT {
		t.Errorf("expected to find PLACEHOLDER_LEAK issue for JWT_SECRET")
	}
	if !foundInsecurePayment {
		t.Errorf("expected to find INSECURE_URL issue for PAYMENT_GATEWAY_URL")
	}
	if !foundTypeMismatchPort {
		t.Errorf("expected to find TYPE_MISMATCH issue for METRICS_PORT")
	}
}

func TestAnalyzer_StagingParity(t *testing.T) {
	testdataDir := filepath.Join("..", "..", "testdata")

	baseFile, err := parser.ParseFile(filepath.Join(testdataDir, ".env.example"))
	if err != nil {
		t.Fatalf("failed to parse .env.example: %v", err)
	}

	stageFile, err := parser.ParseFile(filepath.Join(testdataDir, ".env.staging"))
	if err != nil {
		t.Fatalf("failed to parse .env.staging: %v", err)
	}

	report, err := Analyze(baseFile, []*parser.EnvFile{stageFile}, false)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// In non-strict mode without critical drift, staging should pass
	if !report.Passed {
		t.Errorf("expected staging environment to pass in non-strict mode, got failed")
	}

	// Verify EXTRA_KEY detected for STAGING_DEBUG_BANNER
	foundExtra := false
	for _, issue := range report.Issues {
		if issue.Key == "STAGING_DEBUG_BANNER" && issue.IssueType == "EXTRA_KEY" {
			foundExtra = true
			break
		}
	}
	if !foundExtra {
		t.Errorf("expected EXTRA_KEY for STAGING_DEBUG_BANNER")
	}
}

func TestAnalyzer_StrictMode(t *testing.T) {
	testdataDir := filepath.Join("..", "..", "testdata")

	baseFile, _ := parser.ParseFile(filepath.Join(testdataDir, ".env.example"))
	stageFile, _ := parser.ParseFile(filepath.Join(testdataDir, ".env.staging"))

	// In strict mode, any warnings cause failure
	report, err := Analyze(baseFile, []*parser.EnvFile{stageFile}, true)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if report.Stats.WarningCount > 0 && report.Passed {
		t.Errorf("strict mode should fail when warnings are present")
	}
}

func TestAnalyzer_GenerateSchema(t *testing.T) {
	input := `
APP_NAME=my-app
PORT=8080
DEBUG=true
API_KEY=secret-token-key-1234
`
	file, err := parser.ParseString(input, ".env")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	schema := GenerateSchema(file)
	if !strings.Contains(schema, "PORT=8080 # type: PORT") {
		t.Errorf("expected PORT type hint in schema, got:\n%s", schema)
	}
	if !strings.Contains(schema, "DEBUG=false # type: BOOLEAN") {
		t.Errorf("expected DEBUG boolean in schema, got:\n%s", schema)
	}
}
