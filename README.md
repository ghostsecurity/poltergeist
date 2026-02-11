![Poltergeist Logo](./docs/poltergeist.png)

# Poltergeist - Resurrected

A performant secret scanner for source code.

### Features

- **Multiple Pattern Support**: Scan with multiple patterns simultaneously for maximum efficiency
- **Multi-Engine Architecture**: Uses Hyperscan/Vectorscan for multi-pattern matching, with fallback to Go regex for single patterns
- **YAML Rule Files**: Easily author rule patterns in YAML
- **Flexible Input**: Support command-line patterns, YAML files, or combination of both
- **Binary File Filtering**: Skips many non-text file types to reduce processing overhead
- **Performance Metrics**: Tracks files scanned, content size, and performance statistics

### Performance Trade-offs

Some decisions were made in the interest of performance and simplicity:

- We assume we are scanning source code, so we scan line-by-line
- We don't scan binary files
- We don't scan overly large files
- We don't unpack archives
- We make trade-offs with Hyperscan to exploit its strengths (i.e. `Caseless`, `DotAll`, `SingleMatch` flags)
- Hyperscan is not always faster than Go regex. For small patterns and few files, Go regex is faster.
- Hyperscan doesn't support capture groups, so we use our own quick match to refine the line match down to an exact `from` and `to`.

### Goals & Roadmap

- When used as a library, the intent is to present matches found by Poltergeist as "secret candidates" to a Ghost Platform "secret agent" (with surrounding content near the secret) to validate intent - i.e. does this look like a valid secret being used in the codebase?.
- Recent [research has shown](https://arxiv.org/html/2504.18784v1) that adding an LLM validation layer dramatically improves the accuracy of secret detection.

### Installation

#### Pre-built Releases (Recommended)

Download the latest release for your platform from [GitHub Releases](https://github.com/ghostsecurity/poltergeist/releases).

**Supported Platforms:**
- Linux (x86_64, ARM64) - statically linked with Vectorscan
- macOS (Intel & Apple Silicon) - statically linked with Vectorscan
- Windows (x86_64) - statically linked with Vectorscan (built with MinGW)

Release binaries have no external dependencies.

```bash
# Linux/macOS
curl -L https://github.com/ghostsecurity/poltergeist/releases/download/v2.0.0/poltergeist_linux_amd64.tar.gz | tar xz
./poltergeist --version

# Or extract and move to PATH
tar xzf poltergeist_*.tar.gz
sudo mv poltergeist /usr/local/bin/
```

```powershell
# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/ghostsecurity/poltergeist/releases/download/v2.0.0/poltergeist_windows_amd64.zip" -OutFile "poltergeist.zip"
Expand-Archive -Path poltergeist.zip -DestinationPath .
.\poltergeist.exe --version
```

#### Verifying Release Signatures

All release artifacts are signed with [Sigstore cosign](https://github.com/sigstore/cosign) for supply chain security.

```bash
# Install cosign
brew install cosign  # macOS
# or download from https://github.com/sigstore/cosign/releases

# Verify a release artifact
cosign verify-blob poltergeist_linux_amd64.tar.gz \
  --bundle poltergeist_linux_amd64.tar.gz.sigstore.json \
  --certificate-identity-regexp 'https://github.com/ghostsecurity/poltergeist/.github/workflows/release.yml' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

#### Platform-Specific Notes

**macOS Security Warning:**

When running the binary on macOS, you may see a Gatekeeper warning. This is because the binary is not signed with an Apple Developer certificate. To bypass:

```bash
# Remove quarantine attribute
xattr -d com.apple.quarantine ./poltergeist

# Or right-click the binary in Finder and select "Open"
```

The binary is safe to run - verify with cosign signatures above.

#### Building from Source

If you want to build from source, you'll need Vectorscan installed:

**macOS:**
```bash
brew install vectorscan
```

**Linux:**
```bash
# Ubuntu/Debian
sudo apt-get install cmake ragel libboost-dev pkg-config

# Then build Vectorscan from source (see scripts/build-vectorscan.sh)
bash scripts/build-vectorscan.sh
```

**Windows (requires MSYS2):**
```bash
# Install MSYS2 from https://www.msys2.org/
# Open MSYS2 MINGW64 terminal

# Install dependencies
pacman -S --needed base-devel git \
  mingw-w64-x86_64-gcc \
  mingw-w64-x86_64-cmake \
  mingw-w64-x86_64-boost \
  mingw-w64-x86_64-ragel \
  mingw-w64-x86_64-pcre \
  mingw-w64-x86_64-sqlite3 \
  mingw-w64-x86_64-pkg-config

# Build Vectorscan
bash scripts/build-vectorscan-windows.sh

# Build standalone binary (in MINGW64 terminal)
CGO_ENABLED=1 \
CGO_CFLAGS="-I$(pwd)/build/vectorscan/windows_amd64/include" \
CGO_LDFLAGS="-L$(pwd)/build/vectorscan/windows_amd64/lib -lhs -static" \
go build -ldflags "-s -w" -o poltergeist.exe ./cmd/poltergeist
```

**Build:**
```bash
# Linux/macOS
make build
```

### About Vectorscan

Poltergeist uses [Vectorscan](https://github.com/VectorCamp/vectorscan), a portable fork of Intel's Hyperscan, on all platforms (Linux, macOS, and Windows).

Vectorscan provides high-performance multi-pattern matching with aggressive optimizations.
Some advanced regex features (backtracking, lookbehind, lookahead, capture groups) are not supported.

Despite these limitations, rule patterns are written with extended regex syntax for
flexibility. While initial matches use Hyperscan/Vectorscan, the final match location and capture
groups are refined with Go regex for maximum compatibility.

## Build from Source

```bash
make build
```

### Run

#### Usage

```bash
./poltergeist [options] <directory_path|file_path> [pattern1] [pattern2] ...
```

#### Options

- `-engine string` - Pattern engine: 'auto' (default), 'go', or 'hyperscan'
- `-rules string` - YAML file or directory containing pattern rules
- `-format string` - Output format: 'text' (default), 'json', or 'md'
- `-output string` - Write output to file (auto-detects format from .json or .md extension)
- `-no-color` - Disable colored output (text format only)
- `-dnr` - Do not redact - show full matches
- `-low-entropy` - Show matches that don't meet minimum entropy requirements

#### Examples

**Basic scan with default settings:**

```bash
./poltergeist /path/to/code
```

**Output formats:**

```bash
# Text output (default, colored)
./poltergeist /path/to/code

# JSON output
./poltergeist --format json /path/to/code

# Markdown report
./poltergeist --format md /path/to/code

# Write to file (auto-detects format)
./poltergeist --output report.json /path/to/code
./poltergeist --output report.md /path/to/code
```

**Custom patterns:**

```bash
# Single pattern
./poltergeist /path/to/code "api[_-]?key"

# YAML rule files
./poltergeist -rules=custom-rules.yaml /path/to/code
./poltergeist -rules=./rules /path/to/code

# Combine YAML file + additional patterns
./poltergeist -rules=custom.yaml /path/to/code "additional.*pattern"
```

**Engine selection:**

```bash
# Force Vectorscan/Hyperscan engine
./poltergeist -engine=hyperscan /path/to/code

# Force Go regex engine
./poltergeist -engine=go /path/to/code
```

### Library Usage

For usage as a library, see examples in the [examples](./examples) directory.

### Rule Authoring

Read more about how to author rules in [docs/rule-authoring.md](./docs/rule-authoring.md).

### Rules Documentation

See [rules.md](./docs/rules.md) for a detailed list of all current rules.

### Testing

#### Rule Validation

All rule patterns are automatically validated at runtime to ensure they compile.

Run `make test-rules` for more comprehensive validation on all loaded rules.

The rule tests will show failures if any of the following are not met:

- Rule compiles successfully with both Go regex and Hyperscan engines
- Have unique IDs
- Meet formatting and structure requirements (name, description, tags, etc.)
- Pass their defined test cases (`assert` and `assert_not`)

```bash
make test-rules
go test -run ^TestRulesValidation$ ./pkg -count=1
--- FAIL: TestRulesValidation (0.07s)
    rule_test.go:45: Testing on platform: darwin/arm64
    rule_test.go:49: Hyperscan available: true
    --- FAIL: TestRulesValidation/ghost.aws.1 (0.00s)
        --- FAIL: TestRulesValidation/ghost.aws.1/assert_not_2 (0.00s)
            rule_test.go:207: Rule ghost.aws.1 pattern should not match assert_not case 2, but does (Hyperscan)
            rule_test.go:212: Rule ghost.aws.1 pattern should not match assert_not case 2, but does (Go)
FAIL
FAIL    github.com/ghostsecurity/poltergeist/pkg        0.217s
FAIL
make: *** [test-rules] Error 1
```

### Pattern Engines

#### Automatic Engine Selection (Default)

The scanner selects the optimal engine:

- **Single pattern**: Uses Go regex (faster compilation, good performance)
- **Multiple patterns**: Uses Hyperscan if available (massive performance gain for multiple patterns)
- **Fallback**: Uses Go regex if Hyperscan is unavailable

### Configuration

The current resource configuration is:

- **Worker Count**: `2 × CPU cores`
- **Max File Size**: 100MB (files larger than this are skipped)
- **Buffer Size**: 128KB read buffer, 10MB max line length
- **Pattern Matching**: Case-sensitive regex by default, enable `(?i)` in pattern for case-insensitive matching

Further benchmarking is required to determine the optimal configuration.

### Binary File Detection

The scanner skips binary files using the following heuristics:

1. **Extension-based filtering**: Known binary extensions (`.exe`, `.jpg`, `.zip`, etc.)
2. **Content analysis**: Null byte detection in first 512 bytes
3. **Heuristic analysis**: Files with >30% non-printable characters are considered binary

### Acknowledgments

We'd like to thank the following projects for providing inspiration for Poltergeist and doing tremendous work in the secret scanning space:

- [trufflehog](https://github.com/trufflesecurity/trufflehog)
- [noseyparker](https://github.com/praetorian-inc/noseyparker)
- [kingfisher](https://github.com/mongodb/kingfisher)
- [gitleaks](https://github.com/gitleaks/gitleaks)
