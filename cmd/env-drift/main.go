// Package main provides the CLI entry point for env-drift.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/smktelkom-dev/env-drift/internal/analyzer"
	"github.com/smktelkom-dev/env-drift/internal/parser"
	"github.com/smktelkom-dev/env-drift/internal/reporter"
)

var (
	// Version is the application version.
	Version = "0.1.0"
)

func main() {
	var (
		baselinePath   string
		targetPathsStr string
		format         string
		strict         bool
		generateFrom   string
		showVersion    bool
	)

	flag.StringVar(&baselinePath, "baseline", ".env.example", "Path to baseline template file (e.g. .env.example)")
	flag.StringVar(&baselinePath, "b", ".env.example", "Path to baseline template file (shorthand)")
	flag.StringVar(&targetPathsStr, "targets", "", "Comma-separated target env files (e.g. .env.staging,.env.production)")
	flag.StringVar(&targetPathsStr, "t", "", "Comma-separated target env files (shorthand)")
	flag.StringVar(&format, "format", "table", "Output format: table, json, github, markdown")
	flag.StringVar(&format, "f", "table", "Output format (shorthand)")
	flag.BoolVar(&strict, "strict", false, "Strict mode: fail on warnings as well as critical errors")
	flag.StringVar(&generateFrom, "generate-example", "", "Generate .env.example template from specified .env file")
	flag.StringVar(&generateFrom, "g", "", "Generate .env.example template (shorthand)")
	flag.BoolVar(&showVersion, "version", false, "Print version information and exit")
	flag.BoolVar(&showVersion, "v", false, "Print version information and exit (shorthand)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: env-drift [options] [target files...]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  env-drift -baseline .env.example -targets .env.staging,.env.production\n")
		fmt.Fprintf(os.Stderr, "  env-drift -b .env.example .env.local .env.production\n")
		fmt.Fprintf(os.Stderr, "  env-drift -format github -strict -targets .env.production\n")
		fmt.Fprintf(os.Stderr, "  env-drift -generate-example .env > .env.example\n")
	}

	flag.Parse()

	if showVersion {
		fmt.Printf("env-drift version %s\n", Version)
		os.Exit(0)
	}

	// Mode 1: Generate example template schema
	if generateFrom != "" {
		envFile, err := parser.ParseFile(generateFrom)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing file %q: %v\n", generateFrom, err)
			os.Exit(2)
		}
		schema := analyzer.GenerateSchema(envFile)
		fmt.Print(schema)
		os.Exit(0)
	}

	// Mode 2: Multi-environment drift analysis
	var targets []string
	if targetPathsStr != "" {
		for _, part := range strings.Split(targetPathsStr, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed != "" {
				targets = append(targets, trimmed)
			}
		}
	}

	// Also append any non-flag arguments as targets
	for _, arg := range flag.Args() {
		trimmed := strings.TrimSpace(arg)
		if trimmed != "" {
			targets = append(targets, trimmed)
		}
	}

	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no target environment files specified.\n")
		flag.Usage()
		os.Exit(2)
	}

	// Parse baseline
	baselineFile, err := parser.ParseFile(baselinePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading baseline file %q: %v\n", baselinePath, err)
		os.Exit(2)
	}

	// Parse target files
	var targetFiles []*parser.EnvFile
	for _, targetPath := range targets {
		tf, err := parser.ParseFile(targetPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading target file %q: %v\n", targetPath, err)
			os.Exit(2)
		}
		targetFiles = append(targetFiles, tf)
	}

	// Execute analysis
	report, err := analyzer.Analyze(baselineFile, targetFiles, strict)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Analysis error: %v\n", err)
		os.Exit(2)
	}

	// Output report
	if err := reporter.Render(report, format, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "Render error: %v\n", err)
		os.Exit(2)
	}

	if !report.Passed {
		os.Exit(1)
	}
	os.Exit(0)
}
