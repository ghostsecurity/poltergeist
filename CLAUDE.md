# Poltergeist - Agent Guide

Guidance for AI agents and humans working in this repository. For rule-writing
specifics, see [docs/rule-authoring.md](docs/rule-authoring.md). For the
published user documentation, see [ghostsecurity.ai](https://ghostsecurity.ai).

## What Poltergeist Is

Poltergeist is a high-performance secret scanner for source code, shipped both
as a standalone CLI and as an importable Go library under the module path
`github.com/ghostsecurity/poltergeist/v2`. It matches many regex rules at once
using Vectorscan/Hyperscan through CGO, falls back to a pure-Go regex engine
when Hyperscan is unavailable, and applies Shannon-entropy filtering so that
low-entropy matches are treated as likely false positives rather than findings.

## Layout

| Path | Purpose |
|------|---------|
| `cmd/poltergeist/` | CLI entry point. Parses flags, loads rules, scans a path, and prints text, JSON, or Markdown output. |
| `cmd/docs/` | Generates `docs/rules.md` from the embedded rule set. Invoked by `make docs`. |
| `cmd/benchmark/` | Benchmark harness that compares the Go and Hyperscan engines. |
| `pkg/poltergeist.go` | Public library API. `Scanner`, `ScanResult`, `LoadRules`, `LoadRulesFromFile`, `LoadRulesFromDirectory`, `SelectEngine`, `IsHyperscanAvailable`, `NewScanner`. |
| `pkg/engine.go` | The `PatternEngine` interface plus its two implementations, `HyperscanEngine` and `GoRegexEngine`. |
| `pkg/rule.go` | Rule data model, embedded-rule loading, extended-regex normalization, and Shannon entropy. |
| `pkg/rules/` | The 100-plus built-in detection rules, one YAML file per provider, embedded into the binary via `//go:embed`. |
| `rules` | A symlink to `pkg/rules` so the embedded rules are also reachable from the repo root. |
| `pkg/testdata/` | Fixtures used by the package tests. |
| `examples/` | A minimal library-usage example. |

## Key Commands

All routine tasks run through the `Makefile`, so prefer the targets below over
ad-hoc `go` invocations. Run `make help` to list every target.

| Command | What it does |
|---------|--------------|
| `make build` | Build the CLI binary `poltergeist` from `cmd/poltergeist` with `CGO_ENABLED=1`. |
| `make test` | Run the full test suite with `go test -v ./...`. |
| `make test-rules` | Run only `TestRulesValidation`, which checks every embedded rule against its own `assert` and `assert_not` cases. |
| `make lint` | Run `golangci-lint run`, whose default linter set includes go vet checks, installing golangci-lint first if it is missing. |
| `make docs` | Regenerate `docs/rules.md` from the embedded rules. |
| `make benchmarks` | Run the benchmark harness across both engines. |

## Build Prerequisites

Building and testing require the Vectorscan/Hyperscan development headers
because the default engine binds to them through CGO. On Debian and Ubuntu the
package is `libhyperscan-dev`, which is exactly what CI installs before running
`make test` and `make lint`. On macOS install `vectorscan` or `hyperscan` with
Homebrew. When you cannot install the native library, the scanner still works
by selecting the pure-Go regex engine, either automatically through `-engine
auto` or explicitly with `-engine go`, so a Hyperscan-less environment can run
the tool even though it cannot compile the Hyperscan engine.

## Running the CLI

```bash
# Scan a directory with the built-in rules and redacted output.
./poltergeist /path/to/code

# Force the pure-Go engine and emit JSON to a file.
./poltergeist -engine go -format json -output findings.json /path/to/code

# Use a custom rule file or directory instead of the embedded rules.
./poltergeist -rules ./my-rules.yaml /path/to/code
```

The main flags are `-engine` for engine selection across `auto`, `go`, and
`hyperscan`, `-rules` for a custom rule file or directory, `-format` for `text`,
`json`, or `md`, `-output` for writing to a file, `-dnr` to show unredacted
matches, `-low-entropy` to include matches below their entropy threshold, and
`-no-color` to disable terminal coloring.

## Rules

Detection rules live in `pkg/rules/` as one YAML file per provider and are
compiled into the binary at build time, so adding or editing a file there
changes the built-in rule set without any external configuration. Each rule
carries a human name, a machine `id`, a regex `pattern`, an `entropy`
threshold, a `redact` pair giving the number of leading and trailing bytes to
keep when the match is masked, and inline `tests` that the validation suite
enforces. A representative rule looks like this:

```yaml
rules:
  - name: Anthropic API Key
    id: ghost.anthropic.1
    description: Anthropic API key.
    tags: [api, anthropic]
    pattern: |
      (?x)
        \b
          (sk-ant-api\d{2}-(?i)[A-Z0-9_-]{86}-(?i)[A-Z0-9_]{6}AA)
        \b
    entropy: 5.1
    redact: [16, 4]
    tests:
      assert:
        - sk-ant-api03-...AA
      assert_not:
        - sk-ant-admin01-...AA
    history:
      - 2025-08-02 initial version
```

Patterns use the PCRE extended `(?x)` form for readability, and `rule.go`
normalizes that syntax for the Go engine before compilation. After any change
under `pkg/rules/`, run `make docs` to regenerate `docs/rules.md`, because the
Docs workflow fails the pull request when that file is stale. Run `make
test-rules` to confirm the new or edited rule still passes its own assertions.

## Conventions

Tests rely only on the standard library `testing` package with table-driven
cases and `t.Fatalf` or `t.Errorf`, so do not introduce testify or any other
assertion framework. Wrap errors with `fmt.Errorf` and `%w` to preserve the
chain, following the pattern already used throughout `rule.go`. Keep new
detection logic inside `pkg/` so that both the CLI and library consumers benefit
from it, and reserve `cmd/` for thin entry points. Match the existing file
organization rather than introducing new top-level packages.

## Continuous Integration

Pull requests run four required checks. The Test workflow installs
`libhyperscan-dev` and runs `make test`, the Lint workflow installs the same
library and runs `make build` followed by `make lint`, the Docs workflow
confirms `docs/rules.md` is regenerated, and a secret-scanning workflow runs
TruffleHog. Run `make lint`, `make test`, and `make docs` locally before
opening a pull request so these checks pass on the first try.
