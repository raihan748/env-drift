package parser

import (
	"strings"
	"testing"
)

func TestParseString_BasicKeyValues(t *testing.T) {
	input := `
# Configuration for local environment
APP_NAME=my-app
APP_ENV=local
PORT=8080
DEBUG=true
`
	file, err := ParseString(input, ".env.local")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}

	expected := map[string]string{
		"APP_NAME": "my-app",
		"APP_ENV":  "local",
		"PORT":     "8080",
		"DEBUG":    "true",
	}

	for k, want := range expected {
		entry, ok := file.Get(k)
		if !ok {
			t.Errorf("expected key %q to exist", k)
			continue
		}
		if entry.Value != want {
			t.Errorf("key %q: got value %q, want %q", k, entry.Value, want)
		}
	}
}

func TestParseString_QuotedAndMultiline(t *testing.T) {
	input := `
SINGLE_QUOTED='hello world'
DOUBLE_QUOTED="hello \"quoted\" world\nline2"
MULTILINE_VAL="line1
line2
line3"
WITH_COMMENT="secret-token" # inline comment
EXPORTED_VAR=test
`
	file, err := ParseString(input, ".env")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if entry, ok := file.Get("SINGLE_QUOTED"); !ok || entry.Value != "hello world" {
		t.Errorf("SINGLE_QUOTED failed, got %q", entry.Value)
	}

	if entry, ok := file.Get("DOUBLE_QUOTED"); !ok || entry.Value != "hello \"quoted\" world\nline2" {
		t.Errorf("DOUBLE_QUOTED failed, got %q", entry.Value)
	}

	if entry, ok := file.Get("MULTILINE_VAL"); !ok || !strings.Contains(entry.Value, "line2") {
		t.Errorf("MULTILINE_VAL failed, got %q", entry.Value)
	}

	if entry, ok := file.Get("WITH_COMMENT"); !ok || entry.Comment != "inline comment" {
		t.Errorf("WITH_COMMENT comment mismatch, got %q", entry.Comment)
	}
}

func TestParseString_VariableExpansion(t *testing.T) {
	input := `
HOST=127.0.0.1
PORT=3000
BASE_URL="http://${HOST}:${PORT}/api"
`
	file, err := ParseString(input, ".env")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entry, ok := file.Get("BASE_URL")
	if !ok {
		t.Fatalf("BASE_URL not found")
	}

	want := "http://127.0.0.1:3000/api"
	if entry.Value != want {
		t.Errorf("got %q, want %q", entry.Value, want)
	}
}

func TestParseString_UnclosedQuoteError(t *testing.T) {
	input := `
UNCLOSED="this quote is never closed
`
	_, err := ParseString(input, ".env")
	if err == nil {
		t.Fatalf("expected error on unclosed quote, got nil")
	}
}
