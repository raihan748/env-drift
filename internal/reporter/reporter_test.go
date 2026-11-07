package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/smktelkom-dev/env-drift/internal/analyzer"
)

func sampleReport() *analyzer.DriftReport {
	return &analyzer.DriftReport{
		BaselineFile: ".env.example",
		TargetFiles:  []string{".env.production"},
		TotalKeys:    10,
		Passed:       false,
		Stats: analyzer.DriftStats{
			TotalChecked:  2,
			CriticalCount: 1,
			WarningCount:  1,
			InfoCount:     0,
		},
		Issues: []analyzer.DriftIssue{
			{
				Key:         "DATABASE_URL",
				Severity:    analyzer.SeverityCritical,
				IssueType:   "MISSING_KEY",
				SourceFile:  ".env.example",
				TargetFile:  ".env.production",
				Line:        15,
				Message:     "Key DATABASE_URL is missing in .env.production",
				Remediation: "Add DATABASE_URL to .env.production",
			},
			{
				Key:         "PORT",
				Severity:    analyzer.SeverityWarning,
				IssueType:   "TYPE_MISMATCH",
				SourceFile:  ".env.example",
				TargetFile:  ".env.production",
				Line:        4,
				Message:     "Expected PORT, got STRING",
				Remediation: "Format PORT as integer",
			},
		},
	}
}

func TestReporter_GitHubAnnotations(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	err := RenderGitHubAnnotations(report, &buf)
	if err != nil {
		t.Fatalf("RenderGitHubAnnotations failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "::error file=.env.production,line=15,title=MISSING_KEY::Key DATABASE_URL is missing") {
		t.Errorf("expected GitHub error annotation format, got:\n%s", out)
	}
	if !strings.Contains(out, "::warning file=.env.production,line=4,title=TYPE_MISMATCH::Expected PORT, got STRING") {
		t.Errorf("expected GitHub warning annotation format, got:\n%s", out)
	}
}

func TestReporter_JSON(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	err := RenderJSON(report, &buf)
	if err != nil {
		t.Fatalf("RenderJSON failed: %v", err)
	}

	var decoded analyzer.DriftReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("failed to decode JSON output: %v", err)
	}

	if decoded.BaselineFile != report.BaselineFile {
		t.Errorf("got baseline %q, want %q", decoded.BaselineFile, report.BaselineFile)
	}
	if len(decoded.Issues) != len(report.Issues) {
		t.Errorf("got %d issues, want %d", len(decoded.Issues), len(report.Issues))
	}
}

func TestReporter_Markdown(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	err := RenderMarkdown(report, &buf)
	if err != nil {
		t.Fatalf("RenderMarkdown failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "## 🛡️ `env-drift` Analysis Summary") {
		t.Errorf("expected markdown header, got:\n%s", out)
	}
	if !strings.Contains(out, "| 🔴 CRITICAL | `DATABASE_URL` |") {
		t.Errorf("expected markdown critical row, got:\n%s", out)
	}
}

func TestReporter_Table(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	err := RenderTable(report, &buf)
	if err != nil {
		t.Fatalf("RenderTable failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "DATABASE_URL") {
		t.Errorf("expected DATABASE_URL in table output, got:\n%s", out)
	}
	if !strings.Contains(out, "Result: FAILED") {
		t.Errorf("expected failed status in table output, got:\n%s", out)
	}
}
