// Package reporter provides formatting engines for env-drift results, supporting
// terminal ANSI tables, GitHub Actions workflow annotations, JSON, and Markdown.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/smktelkom-dev/env-drift/internal/analyzer"
)

// ANSI color codes for terminal formatting.
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorGray   = "\033[90m"
)

// Render writes the formatted drift report to w using the specified format.
func Render(report *analyzer.DriftReport, format string, w io.Writer) error {
	switch strings.ToLower(format) {
	case "json":
		return RenderJSON(report, w)
	case "github", "actions":
		return RenderGitHubAnnotations(report, w)
	case "markdown", "md":
		return RenderMarkdown(report, w)
	case "table", "text", "":
		return RenderTable(report, w)
	default:
		return fmt.Errorf("unsupported output format %q (allowed: table, json, github, markdown)", format)
	}
}

// RenderJSON serializes the DriftReport as formatted JSON.
func RenderJSON(report *analyzer.DriftReport, w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// RenderGitHubAnnotations prints GitHub Actions workflow commands for annotations.
func RenderGitHubAnnotations(report *analyzer.DriftReport, w io.Writer) error {
	for _, issue := range report.Issues {
		command := "notice"
		switch issue.Severity {
		case analyzer.SeverityCritical:
			command = "error"
		case analyzer.SeverityWarning:
			command = "warning"
		case analyzer.SeverityInfo:
			command = "notice"
		}

		// ::command file={name},line={line},title={title}::{message}
		file := issue.TargetFile
		if file == "" {
			file = issue.SourceFile
		}
		line := issue.Line
		if line <= 0 {
			line = 1
		}

		fmt.Fprintf(w, "::%s file=%s,line=%d,title=%s::%s | Remediation: %s\n",
			command, file, line, issue.IssueType, issue.Message, issue.Remediation)
	}

	if len(report.Issues) == 0 {
		fmt.Fprintln(w, "::notice::No environment drift or security leaks detected. All clean!")
	}

	return nil
}

// RenderMarkdown outputs a GitHub-flavored Markdown table for PR comments or CI summaries.
func RenderMarkdown(report *analyzer.DriftReport, w io.Writer) error {
	fmt.Fprintf(w, "## 🛡️ `env-drift` Analysis Summary\n\n")
	fmt.Fprintf(w, "- **Baseline**: `%s`\n", report.BaselineFile)
	fmt.Fprintf(w, "- **Targets**: `%s`\n", strings.Join(report.TargetFiles, ", "))
	fmt.Fprintf(w, "- **Status**: %s\n\n", map[bool]string{true: "✅ **PASSED**", false: "❌ **FAILED**"}[report.Passed])

	fmt.Fprintf(w, "| Severity | Key | Issue Type | Target File | Line | Message | Remediation |\n")
	fmt.Fprintf(w, "|---|---|---|---|---|---|---|\n")

	for _, issue := range report.Issues {
		badge := "ℹ️ INFO"
		switch issue.Severity {
		case analyzer.SeverityCritical:
			badge = "🔴 CRITICAL"
		case analyzer.SeverityWarning:
			badge = "⚠️ WARNING"
		case analyzer.SeverityInfo:
			badge = "ℹ️ INFO"
		}

		fmt.Fprintf(w, "| %s | `%s` | `%s` | `%s` | %d | %s | %s |\n",
			badge, issue.Key, issue.IssueType, issue.TargetFile, issue.Line,
			escapePipes(issue.Message), escapePipes(issue.Remediation))
	}

	if len(report.Issues) == 0 {
		fmt.Fprintf(w, "\n*No configuration drift or placeholder leaks detected.*\n")
	}

	fmt.Fprintf(w, "\n**Stats**: %d Critical, %d Warnings, %d Info\n",
		report.Stats.CriticalCount, report.Stats.WarningCount, report.Stats.InfoCount)

	return nil
}

// RenderTable outputs a formatted terminal summary table.
func RenderTable(report *analyzer.DriftReport, w io.Writer) error {
	fmt.Fprintf(w, "\n%s=== env-drift: Multi-Environment Schema & Security Auditor ===%s\n", colorBold, colorReset)
	fmt.Fprintf(w, "%sBaseline Template:%s %s\n", colorCyan, colorReset, report.BaselineFile)
	fmt.Fprintf(w, "%sTarget Environments:%s %s\n\n", colorCyan, colorReset, strings.Join(report.TargetFiles, ", "))

	if len(report.Issues) == 0 {
		fmt.Fprintf(w, "%s✔ No drift or placeholder leaks detected! Environments are in sync.%s\n\n", colorGreen, colorReset)
		return nil
	}

	for _, issue := range report.Issues {
		sevTag := "[INFO]"
		sevColor := colorBlue
		switch issue.Severity {
		case analyzer.SeverityCritical:
			sevTag = "[CRITICAL]"
			sevColor = colorRed
		case analyzer.SeverityWarning:
			sevTag = "[WARNING]"
			sevColor = colorYellow
		case analyzer.SeverityInfo:
			sevTag = "[INFO]"
			sevColor = colorCyan
		}

		fmt.Fprintf(w, "%s%s%-10s%s %s%s%s in %s:%d\n",
			colorBold, sevColor, sevTag, colorReset,
			colorBold, issue.Key, colorReset,
			issue.TargetFile, issue.Line)
		fmt.Fprintf(w, "  Type:        %s\n", issue.IssueType)
		fmt.Fprintf(w, "  Message:     %s\n", issue.Message)
		fmt.Fprintf(w, "  %sRemediation:%s %s\n\n", colorGreen, colorReset, issue.Remediation)
	}

	fmt.Fprintf(w, "%sSummary:%s %d critical, %d warnings, %d info (Total keys checked: %d)\n",
		colorBold, colorReset,
		report.Stats.CriticalCount, report.Stats.WarningCount, report.Stats.InfoCount,
		report.TotalKeys)

	if report.Passed {
		fmt.Fprintf(w, "%sResult: PASSED%s\n\n", colorGreen, colorReset)
	} else {
		fmt.Fprintf(w, "%sResult: FAILED (Critical drift detected)%s\n\n", colorRed, colorReset)
	}

	return nil
}

func escapePipes(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
