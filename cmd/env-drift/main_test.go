package main

import (
	"path/filepath"
	"testing"

	"github.com/smktelkom-dev/env-drift/internal/analyzer"
	"github.com/smktelkom-dev/env-drift/internal/parser"
)

func TestEndToEnd_MultiEnvDriftAudit(t *testing.T) {
	testdataDir := filepath.Join("..", "..", "testdata")

	base, err := parser.ParseFile(filepath.Join(testdataDir, ".env.example"))
	if err != nil {
		t.Fatalf("failed to parse baseline: %v", err)
	}

	stage, err := parser.ParseFile(filepath.Join(testdataDir, ".env.staging"))
	if err != nil {
		t.Fatalf("failed to parse staging: %v", err)
	}

	prod, err := parser.ParseFile(filepath.Join(testdataDir, ".env.production"))
	if err != nil {
		t.Fatalf("failed to parse production: %v", err)
	}

	report, err := analyzer.Analyze(base, []*parser.EnvFile{stage, prod}, false)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if report.Passed {
		t.Errorf("expected audit to fail due to critical drift in production")
	}

	if report.Stats.CriticalCount == 0 {
		t.Errorf("expected at least 1 critical issue, got 0")
	}

	t.Logf("Audit completed with %d critical, %d warning, %d info issues",
		report.Stats.CriticalCount, report.Stats.WarningCount, report.Stats.InfoCount)
}
