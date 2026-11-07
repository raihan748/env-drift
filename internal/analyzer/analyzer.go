// Package analyzer implements cross-environment comparison, drift detection,
// type consistency verification, and security vulnerability auditing.
package analyzer

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/smktelkom-dev/env-drift/internal/infer"
	"github.com/smktelkom-dev/env-drift/internal/parser"
	"github.com/smktelkom-dev/env-drift/internal/security"
)

// DriftSeverity denotes the operational impact of a detected configuration issue.
type DriftSeverity string

const (
	SeverityInfo     DriftSeverity = "INFO"
	SeverityWarning  DriftSeverity = "WARNING"
	SeverityCritical DriftSeverity = "CRITICAL"
)

// DriftIssue represents an individual configuration drift or security defect.
type DriftIssue struct {
	Key         string        `json:"key"`
	Severity    DriftSeverity `json:"severity"`
	IssueType   string        `json:"issue_type"`
	SourceFile  string        `json:"source_file"`
	TargetFile  string        `json:"target_file"`
	Line        int           `json:"line"`
	Message     string        `json:"message"`
	Remediation string        `json:"remediation"`
}

// DriftStats provides aggregate statistics of issues by severity.
type DriftStats struct {
	TotalChecked  int `json:"total_checked"`
	CriticalCount int `json:"critical_count"`
	WarningCount  int `json:"warning_count"`
	InfoCount     int `json:"info_count"`
}

// DriftReport encapsulates the holistic cross-environment analysis results.
type DriftReport struct {
	BaselineFile string       `json:"baseline_file"`
	TargetFiles  []string     `json:"target_files"`
	TotalKeys    int          `json:"total_keys"`
	Issues       []DriftIssue `json:"issues"`
	Passed       bool         `json:"passed"`
	Stats        DriftStats   `json:"stats"`
}

// IsProductionEnvironment inspects path/filename to determine if it targets production.
func IsProductionEnvironment(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return strings.Contains(base, "prod") || strings.Contains(base, "live")
}

// IsStagingEnvironment inspects path/filename to determine if it targets staging.
func IsStagingEnvironment(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return strings.Contains(base, "stage") || strings.Contains(base, "staging") ||
		strings.Contains(base, "uat") || strings.Contains(base, "qa")
}

// Analyze executes schema verification and security leak detection between baseline and targets.
func Analyze(baseline *parser.EnvFile, targets []*parser.EnvFile, strict bool) (*DriftReport, error) {
	if baseline == nil {
		return nil, fmt.Errorf("baseline env file cannot be nil")
	}

	report := &DriftReport{
		BaselineFile: baseline.Path,
		TargetFiles:  make([]string, 0, len(targets)),
		Issues:       make([]DriftIssue, 0),
		TotalKeys:    len(baseline.Map),
	}

	for _, target := range targets {
		report.TargetFiles = append(report.TargetFiles, target.Path)
		isProd := IsProductionEnvironment(target.Path)
		isStage := IsStagingEnvironment(target.Path)

		// 1. Check for missing keys (in baseline, absent in target)
		for _, baseKey := range baseline.Keys() {
			baseEntry, _ := baseline.Get(baseKey)
			targetEntry, exists := target.Get(baseKey)

			if !exists {
				report.Issues = append(report.Issues, DriftIssue{
					Key:         baseKey,
					Severity:    SeverityCritical,
					IssueType:   "MISSING_KEY",
					SourceFile:  baseline.Path,
					TargetFile:  target.Path,
					Line:        baseEntry.Line,
					Message:     fmt.Sprintf("Key %q is defined in baseline %s but missing in %s", baseKey, baseline.Path, target.Path),
					Remediation: fmt.Sprintf("Add variable %q to %s", baseKey, target.Path),
				})
				continue
			}

			// 2. Check for empty values in target where baseline was populated
			if strings.TrimSpace(targetEntry.Value) == "" && strings.TrimSpace(baseEntry.Value) != "" {
				report.Issues = append(report.Issues, DriftIssue{
					Key:         baseKey,
					Severity:    SeverityWarning,
					IssueType:   "EMPTY_VALUE",
					SourceFile:  baseline.Path,
					TargetFile:  target.Path,
					Line:        targetEntry.Line,
					Message:     fmt.Sprintf("Key %q has empty value in %s", baseKey, target.Path),
					Remediation: fmt.Sprintf("Provide configured value for %q in %s", baseKey, target.Path),
				})
			}

			// 3. Type inference compatibility check
			baseType := infer.InferType(baseKey, baseEntry.Value)
			targetType := infer.InferType(baseKey, targetEntry.Value)

			if !infer.AreTypesCompatible(baseType, targetType) && targetEntry.Value != "" {
				report.Issues = append(report.Issues, DriftIssue{
					Key:         baseKey,
					Severity:    SeverityWarning,
					IssueType:   "TYPE_MISMATCH",
					SourceFile:  baseline.Path,
					TargetFile:  target.Path,
					Line:        targetEntry.Line,
					Message:     fmt.Sprintf("Type mismatch for key %q: baseline is %s, target is %s (%q)", baseKey, baseType, targetType, targetEntry.Value),
					Remediation: fmt.Sprintf("Cast or format value to conform with type %s", baseType),
				})
			}
		}

		// 4. Check for extra undocumented keys (in target, not in baseline)
		for _, targetKey := range target.Keys() {
			targetEntry, _ := target.Get(targetKey)
			if !baseline.Has(targetKey) {
				report.Issues = append(report.Issues, DriftIssue{
					Key:         targetKey,
					Severity:    SeverityInfo,
					IssueType:   "EXTRA_KEY",
					SourceFile:  baseline.Path,
					TargetFile:  target.Path,
					Line:        targetEntry.Line,
					Message:     fmt.Sprintf("Key %q in %s is not documented in baseline %s", targetKey, target.Path, baseline.Path),
					Remediation: fmt.Sprintf("Document %q in %s to maintain centralized schema parity", targetKey, baseline.Path),
				})
			}
		}

		// 5. Security leak detection (placeholders, dev hosts, insecure URLs)
		for _, targetKey := range target.Keys() {
			targetEntry, _ := target.Get(targetKey)
			leak := security.AnalyzeVariable(targetKey, targetEntry.Value, isProd)
			if leak != nil {
				sev := SeverityWarning
				if isProd {
					sev = SeverityCritical
				} else if isStage {
					sev = SeverityWarning
				} else {
					sev = SeverityInfo
				}

				report.Issues = append(report.Issues, DriftIssue{
					Key:         targetKey,
					Severity:    sev,
					IssueType:   leak.Type,
					SourceFile:  baseline.Path,
					TargetFile:  target.Path,
					Line:        targetEntry.Line,
					Message:     leak.Description,
					Remediation: leak.Remediation,
				})
			}
		}
	}

	// Calculate statistics
	report.Stats.TotalChecked = len(report.Issues)
	for _, issue := range report.Issues {
		switch issue.Severity {
		case SeverityCritical:
			report.Stats.CriticalCount++
		case SeverityWarning:
			report.Stats.WarningCount++
		case SeverityInfo:
			report.Stats.InfoCount++
		}
	}

	// Pass criteria: in normal mode, no critical issues. In strict mode, no critical or warnings.
	if strict {
		report.Passed = report.Stats.CriticalCount == 0 && report.Stats.WarningCount == 0
	} else {
		report.Passed = report.Stats.CriticalCount == 0
	}

	return report, nil
}

// GenerateSchema generates a clean .env.example template from an existing EnvFile.
func GenerateSchema(file *parser.EnvFile) string {
	var sb strings.Builder
	sb.WriteString("# Auto-generated environment schema by env-drift\n")
	sb.WriteString("# Standardized template with type annotations\n\n")

	for _, entry := range file.Entries {
		switch entry.Type {
		case parser.EntryBlank:
			sb.WriteString("\n")
		case parser.EntryComment:
			sb.WriteString("# ")
			sb.WriteString(entry.Comment)
			sb.WriteString("\n")
		case parser.EntryVariable:
			inferred := infer.InferType(entry.Key, entry.Value)
			maskedVal := placeholderForType(inferred, entry.Key)
			sb.WriteString(fmt.Sprintf("%s=%s # type: %s\n", entry.Key, maskedVal, inferred))
		}
	}

	return sb.String()
}

func placeholderForType(t infer.InferredType, key string) string {
	switch t {
	case infer.TypeBoolean:
		return "false"
	case infer.TypePort:
		return "8080"
	case infer.TypeInteger:
		return "10"
	case infer.TypeFloat:
		return "1.0"
	case infer.TypeDuration:
		return "30s"
	case infer.TypeUUID:
		return "00000000-0000-0000-0000-000000000000"
	case infer.TypeEmail:
		return "user@example.com"
	case infer.TypeURL:
		return "https://api.example.com"
	case infer.TypeJSON:
		return `"{}"`
	case infer.TypeSecret:
		return `"your-secret-here"`
	default:
		return `"example-value"`
	}
}
