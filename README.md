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
- Windows (x86_64) - statically linked with Intel Hyperscan

Release binaries have no external dependencies (except standard system libraries on macOS).

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

#### Building from Source

If you want to build from source, you'll need Vectorscan (Linux/macOS) or Intel Hyperscan (Windows) installed:

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

**Windows:**
```powershell
# Install Visual Studio 2017+ with C++ tools
# Install CMake and vcpkg

# Install dependencies
vcpkg install boost-system:x64-windows-static boost-filesystem:x64-windows-static boost-thread:x64-windows-static ragel:x64-windows-static pcre:x64-windows-static

# Build Intel Hyperscan
pwsh scripts/build-hyperscan-windows.ps1
```

**Build:**
```bash
# Linux/macOS
make build

# Windows
go build -o poltergeist.exe ./cmd/poltergeist
```

### About Vectorscan/Hyperscan

Poltergeist uses:
- **Vectorscan** (a portable fork of Intel's Hyperscan) on Linux and macOS
- **Intel Hyperscan** on Windows (official Windows support)

Both provide high-performance multi-pattern matching with aggressive optimizations.
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

### Benchmarks

On a typical development machine scanning a medium-sized codebase:

- **~1,000 files**: 50-100ms
- **~10,000 files**: 200-500ms
- **~100,000 files**: 2-5 seconds

The Go engine is included primarily for benchmark reference purposes.

### Results

Running against some real-world [content](https://github.com/torvalds/linux) with a few seeded secrets.

| Engine    | Rules | Compile(ms) | Scan  | Total | Matches | Throughput (MB/s) |
| --------- | ----- | ----------- | ----- | ----- | ------- | ----------------- |
| go        | 16    | 0.3         | 13.4s | 13.4s | 20      | 108.27            |
| hyperscan | 16    | 79.1        | 8.2s  | 8.2s  | 20      | 177.44            |
| go        | 26    | 0.4         | 19.7s | 19.7s | 20      | 73.73             |
| hyperscan | 26    | 109.1       | 8.1s  | 8.2s  | 20      | 178.92            |
| go        | 66    | 0.6         | 45.4s | 45.4s | 20      | 32.04             |
| hyperscan | 66    | 222.1       | 8.2s  | 8.4s  | 20      | 177.49            |
| go        | 116   | 1.1         | 1m17s | 1m17s | 20      | 18.82             |
| hyperscan | 116   | 356.3       | 8.0s  | 8.4s  | 20      | 180.15            |
| go        | 216   | 1.8         | 2m24s | 2m24s | 20      | 10.09             |
| hyperscan | 216   | 639.6       | 8.1s  | 8.7s  | 20      | 179.54            |
| go        | 516   | 4.6         | 5m45s | 5m45s | 20      | 4.21              |
| hyperscan | 516   | 1546.4      | 8.1s  | 8.5s  | 20      | 177.53            |
| go        | 1016  | 8.5         | 11m9s | 11m9s | 20      | 2.17              |
| hyperscan | 1016  | 2942.7      | 8.6s  | 11.2s | 20      | 176.02            |

| Rules | Go Total(ms) | HS Total(ms) | Speedup |
| ----- | ------------ | ------------ | ------- |
| 16    | 13443.3      | 8281.4       | 1.62x   |
| 26    | 19739.9      | 8243.5       | 2.39x   |
| 66    | 45419.3      | 8422.4       | 5.39x   |
| 116   | 77335.4      | 8435.3       | 9.17x   |
| 216   | 144174.3     | 8745.9       | 16.48x  |
| 516   | 345988.1     | 9744.4       | 35.51x  |
| 1016  | 669583.4     | 11211.1      | 59.72x  |

| Tool (all hs/vs based)                                       | Rules | ~Time (1.4GB content) |
| ------------------------------------------------------------ | ----- | --------------------- |
| poltergeist                                                  | 16    | 8s                    |
| poltergeist                                                  | 26    | 8s                    |
| poltergeist                                                  | 66    | 8s                    |
| poltergeist                                                  | 116   | 8s                    |
| [noseyparker](https://github.com/praetorian-inc/noseyparker) | 162   | 5s                    |
| poltergeist                                                  | 216   | 8s                    |
| [kingfisher](https://github.com/mongodb/kingfisher)          | 256   | 6s                    |
| poltergeist                                                  | 516   | 8s                    |
| poltergeist                                                  | 1016  | 9s                    |

## TODO

- [x] Track whether minimum entropy is met for matches
- [ ] Track multiple matches per line
- [ ] If multiple matches, ignore generic rule matches if there is a non-generic match
- [ ] Incorporate plain english stop words to reduce false positives
