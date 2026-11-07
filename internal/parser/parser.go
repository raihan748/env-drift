// Package parser provides a strict lexer and AST parser for .env files.
// It supports comments, inline comments, variable expansion (${FOO}),
// double/single quotes, multiline values, and export prefixes.
package parser

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode"
)

// EntryType represents the category of an environment file line.
type EntryType int

const (
	// EntryVariable denotes a key-value assignment.
	EntryVariable EntryType = iota
	// EntryComment denotes a full line comment.
	EntryComment
	// EntryBlank denotes an empty or whitespace-only line.
	EntryBlank
)

// String returns human-readable representation of EntryType.
func (t EntryType) String() string {
	switch t {
	case EntryVariable:
		return "VARIABLE"
	case EntryComment:
		return "COMMENT"
	case EntryBlank:
		return "BLANK"
	default:
		return "UNKNOWN"
	}
}

// EnvEntry represents a parsed element in a .env file.
type EnvEntry struct {
	Type      EntryType `json:"type"`
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	Raw       string    `json:"raw"`
	Line      int       `json:"line"`
	Comment   string    `json:"comment,omitempty"`
	IsQuoted  bool      `json:"is_quoted"`
	QuoteChar rune      `json:"quote_char,omitempty"`
}

// EnvFile represents the AST of an entire parsed .env file.
type EnvFile struct {
	Path    string              `json:"path"`
	Entries []EnvEntry          `json:"entries"`
	Map     map[string]EnvEntry `json:"map"`
}

// Get returns the EnvEntry for the given key, or false if not found.
func (f *EnvFile) Get(key string) (EnvEntry, bool) {
	entry, ok := f.Map[key]
	return entry, ok
}

// Has returns true if the key exists in the parsed file.
func (f *EnvFile) Has(key string) bool {
	_, ok := f.Map[key]
	return ok
}

// Keys returns a slice of all variable keys in declaration order.
func (f *EnvFile) Keys() []string {
	var keys []string
	for _, entry := range f.Entries {
		if entry.Type == EntryVariable && entry.Key != "" {
			keys = append(keys, entry.Key)
		}
	}
	return keys
}

// ParseFile parses a .env file from the given filesystem path.
func ParseFile(path string) (*EnvFile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open env file %q: %w", path, err)
	}
	defer file.Close()

	return ParseReader(file, path)
}

// ParseString parses .env content from a string.
func ParseString(content, path string) (*EnvFile, error) {
	return ParseReader(strings.NewReader(content), path)
}

// ParseBytes parses .env content from a byte slice.
func ParseBytes(data []byte, path string) (*EnvFile, error) {
	return ParseReader(strings.NewReader(string(data)), path)
}

var (
	varExpansionRegex = regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}|\$([a-zA-Z_][a-zA-Z0-9_]*)`)
)

// ParseReader parses a .env stream into an EnvFile AST.
func ParseReader(r io.Reader, path string) (*EnvFile, error) {
	scanner := bufio.NewScanner(r)
	envFile := &EnvFile{
		Path:    path,
		Entries: make([]EnvEntry, 0),
		Map:     make(map[string]EnvEntry),
	}

	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		rawLine := scanner.Text()
		trimmed := strings.TrimSpace(rawLine)

		// 1. Blank lines
		if len(trimmed) == 0 {
			envFile.Entries = append(envFile.Entries, EnvEntry{
				Type: EntryBlank,
				Raw:  rawLine,
				Line: lineNumber,
			})
			continue
		}

		// 2. Full-line comment
		if strings.HasPrefix(trimmed, "#") {
			commentText := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
			envFile.Entries = append(envFile.Entries, EnvEntry{
				Type:    EntryComment,
				Raw:     rawLine,
				Line:    lineNumber,
				Comment: commentText,
			})
			continue
		}

		// 3. Variable line
		lineContent := trimmed
		if strings.HasPrefix(lineContent, "export ") {
			lineContent = strings.TrimSpace(strings.TrimPrefix(lineContent, "export "))
		}

		eqIdx := strings.Index(lineContent, "=")
		if eqIdx == -1 {
			// Malformed or flag variable without equals
			key := strings.TrimSpace(lineContent)
			entry := EnvEntry{
				Type: EntryVariable,
				Key:  key,
				Raw:  rawLine,
				Line: lineNumber,
			}
			envFile.Entries = append(envFile.Entries, entry)
			envFile.Map[key] = entry
			continue
		}

		key := strings.TrimSpace(lineContent[:eqIdx])
		valPart := strings.TrimSpace(lineContent[eqIdx+1:])

		// Check for multiline or quoted string
		val, inlineComment, isQuoted, quoteChar, endLine, err := parseValue(valPart, scanner, &lineNumber)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}

		// Perform variable expansion on unquoted or double-quoted strings
		if !isQuoted || quoteChar == '"' {
			val = expandVariables(val, envFile.Map)
		}

		entry := EnvEntry{
			Type:      EntryVariable,
			Key:       key,
			Value:     val,
			Raw:       rawLine,
			Line:      lineNumber - (endLine - lineNumber), // keep starting line
			Comment:   inlineComment,
			IsQuoted:  isQuoted,
			QuoteChar: quoteChar,
		}

		envFile.Entries = append(envFile.Entries, entry)
		envFile.Map[key] = entry
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading env stream: %w", err)
	}

	return envFile, nil
}

// parseValue extracts value, inline comment, quote type, and handles multiline inputs.
func parseValue(rawVal string, scanner *bufio.Scanner, currentLine *int) (val string, inlineComment string, isQuoted bool, quoteChar rune, finalLine int, err error) {
	finalLine = *currentLine
	if len(rawVal) == 0 {
		return "", "", false, 0, finalLine, nil
	}

	firstChar := rune(rawVal[0])

	// Single-quoted string
	if firstChar == '\'' {
		return parseQuoted(rawVal, '\'', scanner, currentLine)
	}

	// Double-quoted string
	if firstChar == '"' {
		return parseQuoted(rawVal, '"', scanner, currentLine)
	}

	// Unquoted string: extract inline comment if present
	// An inline comment must be preceded by whitespace (e.g. `VAL # comment`)
	inComment := false
	var buf strings.Builder
	for i := 0; i < len(rawVal); i++ {
		c := rawVal[i]
		if c == '#' && (i > 0 && unicode.IsSpace(rune(rawVal[i-1]))) {
			inComment = true
			inlineComment = strings.TrimSpace(rawVal[i+1:])
			break
		}
		buf.WriteByte(c)
	}

	val = strings.TrimSpace(buf.String())
	_ = inComment
	return val, inlineComment, false, 0, finalLine, nil
}

// parseQuoted handles single or double quoted strings, including multiline continuation.
func parseQuoted(rawVal string, quote rune, scanner *bufio.Scanner, currentLine *int) (string, string, bool, rune, int, error) {
	var b strings.Builder
	// strip leading quote
	remaining := rawVal[1:]
	escaped := false
	closed := false
	var inlineComment string

	for {
		for i := 0; i < len(remaining); i++ {
			c := rune(remaining[i])

			if quote == '\'' {
				// Single quotes: no escape parsing
				if c == '\'' {
					closed = true
					// Check for inline comment after closing quote
					after := strings.TrimSpace(remaining[i+1:])
					if strings.HasPrefix(after, "#") {
						inlineComment = strings.TrimSpace(strings.TrimPrefix(after, "#"))
					}
					return b.String(), inlineComment, true, quote, *currentLine, nil
				}
				b.WriteRune(c)
			} else {
				// Double quotes: parse escape sequences
				if escaped {
					switch c {
					case 'n':
						b.WriteRune('\n')
					case 'r':
						b.WriteRune('\r')
					case 't':
						b.WriteRune('\t')
					case '\\':
						b.WriteRune('\\')
					case '"':
						b.WriteRune('"')
					case '$':
						b.WriteRune('$')
					default:
						b.WriteRune('\\')
						b.WriteRune(c)
					}
					escaped = false
					continue
				}

				if c == '\\' {
					escaped = true
					continue
				}

				if c == '"' {
					closed = true
					// Check for inline comment after closing quote
					after := strings.TrimSpace(remaining[i+1:])
					if strings.HasPrefix(after, "#") {
						inlineComment = strings.TrimSpace(strings.TrimPrefix(after, "#"))
					}
					return b.String(), inlineComment, true, quote, *currentLine, nil
				}

				b.WriteRune(c)
			}
		}

		if closed {
			break
		}

		// Multiline: read next line
		if !scanner.Scan() {
			return b.String(), "", true, quote, *currentLine, fmt.Errorf("unclosed quote %c starting at line %d", quote, *currentLine)
		}
		*currentLine++
		b.WriteRune('\n')
		remaining = scanner.Text()
	}

	return b.String(), inlineComment, true, quote, *currentLine, nil
}

// expandVariables performs expansion of ${VAR} or $VAR against parsed map and environment.
func expandVariables(val string, envMap map[string]EnvEntry) string {
	return varExpansionRegex.ReplaceAllStringFunc(val, func(m string) string {
		varName := m[1:]
		if strings.HasPrefix(m, "${") && strings.HasSuffix(m, "}") {
			varName = m[2 : len(m)-1]
		}

		if entry, ok := envMap[varName]; ok {
			return entry.Value
		}
		if sysVal, exists := os.LookupEnv(varName); exists {
			return sysVal
		}
		return m // Keep unexpanded if not found
	})
}
