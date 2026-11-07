# 🛡️ `env-drift`

> **High-Performance Multi-Environment `.env` Schema Validator, Type Inference Engine, and Secret Leak Auditor in Pure Go.**

[![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Build Status](https://img.shields.io/badge/tests-100%25%20passing-brightgreen)](https://github.com/smktelkom-dev/env-drift)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Dependencies](https://img.shields.io/badge/dependencies-0%20external-success)](https://pkg.go.dev/std)

---

## 📌 Executive Summary

Configuration drift across `.env.example`, `.env.local`, `.env.staging`, and `.env.production` is a leading cause of production outages, deployment delays, and critical security breaches. Development teams frequently:
1. **Forget to update `.env.example`** when adding new mandatory keys in code, breaking local dev setups for colleagues.
2. **Leave placeholder credentials** (`changeme`, `your-api-key`, `password`) in staging and production manifests.
3. **Point production configurations to development hosts** (`localhost`, `127.0.0.1`).
4. **Introduce subtle type contradictions** (e.g. passing a string `"not_a_port"` where an integer port between `1-65535` is expected).

`env-drift` is an ultra-fast, zero-dependency static analysis CLI tool that parses multi-environment `.env` configurations, computes AST schema diffs, infers semantic data types, detects placeholder leaks via Shannon entropy, and generates hardened schemas.

---

## 🏛️ Architecture & Dataflow

```
   ┌──────────────────────────────────────────────────────────────┐
   │                  Baseline Template (.env.example)            │
   └──────────────────────────────┬───────────────────────────────┘
                                  │
                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │                     Strict AST Parser                        │
   │  • Quote lexer (' & ")       • Multiline string buffer       │
   │  • Variable expansion (${})  • Line & inline comment capture │
   └──────────────────────────────┬───────────────────────────────┘
                                  │
                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │               Heuristic Type Inference Engine                │
   │  • PORT (1-65535)            • UUID (RFC 4122)               │
   │  • URL / URI validation      • JSON syntax validator         │
   │  • Duration (Go/human)       • Email (RFC 5322)              │
   │  • Shannon Entropy (>3.8)    • BOOLEAN, INTEGER, FLOAT       │
   └──────────────────────────────┬───────────────────────────────┘
                                  │
                 ┌────────────────┴────────────────┐
                 ▼                                 ▼
   ┌───────────────────────────┐     ┌────────────────────────────┐
   │  Drift Matrix Comparator  │     │  Security Leak Detector    │
   │  • Missing Keys (CRITICAL)│     │  • Placeholders / Dummies  │
   │  • Undocumented Keys      │     │  • Localhost in Production │
   │  • Type Contradictions    │     │  • Insecure HTTP URLs      │
   │  • Empty Required Values  │     │  • Low-Entropy Secrets     │
   └─────────────┬─────────────┘     └─────────────┬──────────────┘
                 │                                 │
                 └────────────────┬────────────────┘
                                  │
                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │                   Multi-Format Reporters                     │
   │  • ANSI Terminal Table        • GitHub Actions (::error::)   │
   │  • Structured JSON (CI)       • GitHub-flavored Markdown     │
   └──────────────────────────────────────────────────────────────┘
```

---

## ✨ Key Features

- **Strict AST Parser**: Full support for single quotes (`'...'`), double quotes (`"..."`), escape sequences (`\n`, `\t`, `\"`), multiline values, inline comments (`# ...`), and recursive variable interpolation (`${VAR}`).
- **Semantic Type Inference**: Automatically classifies configuration entries into 11 semantic types without schema declarations: `PORT`, `INTEGER`, `FLOAT`, `BOOLEAN`, `URL`, `EMAIL`, `UUID`, `DURATION`, `JSON`, `SECRET`, and `STRING`.
- **Shannon Entropy & Placeholder Scanner**: Calculates exact Shannon information entropy ($H(X) = -\sum P(x) \log_2 P(x)$) and compares against known dummy dictionaries (`changeme`, `your-api-key`, mock OpenAI / AWS / Stripe keys) to flag leaked placeholders before deploying.
- **Zero External Dependencies**: Implemented strictly using the Go standard library (`bufio`, `net/url`, `regexp`, `encoding/json`, `math`). Compiles in under 2 seconds.
- **Native CI/CD Integration**: Supports GitHub Actions workflow annotations (`::error::` and `::warning::`) out-of-the-box, instantly highlighting the offending line in pull request diffs.

---

## 🚀 Installation & Quick Start

### Build from Source
```bash
# Clone the repository
git clone https://github.com/smktelkom-dev/env-drift.git
cd env-drift

# Build standalone binary into bin/
go build -o bin/env-drift.exe ./cmd/env-drift
```

### Basic Execution
```bash
# Compare baseline against production
./bin/env-drift.exe -baseline .env.example -targets .env.production

# Compare multiple environments simultaneously
./bin/env-drift.exe -b .env.example .env.staging .env.production
```

---

## 🛠️ CLI Reference & Flags

| Flag | Shorthand | Default | Description |
|---|---|---|---|
| `-baseline` | `-b` | `.env.example` | Path to baseline template configuration file |
| `-targets` | `-t` | `""` | Comma-separated list of target environment files |
| `-format` | `-f` | `table` | Output format: `table`, `json`, `github`, `markdown` |
| `-strict` | | `false` | Strict mode: exit code `1` on warnings as well as critical errors |
| `-generate-example` | `-g` | `""` | Generate a sanitized `.env.example` schema from an existing `.env` file |
| `-version` | `-v` | `false` | Print application version and exit |

---

## 💡 Example Scenarios

### 1. Generating a Clean `.env.example` from an Existing `.env`
```bash
./bin/env-drift.exe -generate-example .env.production > .env.example
```
**Output (`.env.example`):**
```dotenv
# Auto-generated environment schema by env-drift
# Standardized template with type annotations

PORT=8080 # type: PORT
DATABASE_URL=https://api.example.com # type: URL
DEBUG=false # type: BOOLEAN
JWT_SECRET="your-secret-here" # type: SECRET
```

### 2. Outputting GitHub Actions Annotations in Pull Requests
```bash
./bin/env-drift.exe -format github -strict -b .env.example .env.production
```
**Output:**
```
::error file=.env.production,line=14,title=PLACEHOLDER_LEAK::Placeholder detected for "JWT_SECRET": contains placeholder token "changeme" | Remediation: Replace dummy placeholder with genuine secure credential
::error file=.env.production,line=19,title=MISSING_KEY::Key "ALLOWED_ORIGINS" is defined in baseline .env.example but missing in .env.production | Remediation: Add variable "ALLOWED_ORIGINS" to .env.production
::warning file=.env.production,line=17,title=INSECURE_URL::Production key "PAYMENT_GATEWAY_URL" uses unencrypted HTTP protocol | Remediation: Migrate to HTTPS or TLS-encrypted endpoint
::warning file=.env.production,line=18,title=TYPE_MISMATCH::Type mismatch for key "METRICS_PORT": baseline is PORT, target is STRING ("not_a_port") | Remediation: Cast or format value to conform with type PORT
```

### 3. Emitting JSON for Automation Scripts
```bash
./bin/env-drift.exe -format json -b .env.example .env.staging
```

---

## 🔄 GitHub Actions CI/CD Pipeline Integration

Add `env-drift` to your `.github/workflows/env-check.yml` to automatically reject pull requests with broken configurations:

```yaml
name: Configuration Parity & Secret Audit

on:
  pull_request:
    paths:
      - '**/.env*'

jobs:
  env-audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.26'

      - name: Build env-drift
        run: go build -o /usr/local/bin/env-drift ./cmd/env-drift

      - name: Audit Environment Files
        run: |
          env-drift -format github -strict \
            -baseline .env.example \
            -targets .env.staging,.env.production
```

---

## 🧪 Test Suite & Verification

The test suite covers:
- Strict `.env` parsing with escape sequences, unicode, inline comments, and multiline values.
- Table-driven type inference heuristics (20+ test cases).
- Shannon entropy calculations and mock API key signatures.
- Multi-environment matrix comparison on realistic test fixtures in `testdata/`.

To run the complete test suite:
```bash
go test -v ./...
```

---

## 👥 Authors & License

Developed with ❤️ by the **SMK Telkom Makassar Developer Team**.  
Licensed under the [MIT License](LICENSE).
