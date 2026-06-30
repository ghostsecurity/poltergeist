![Poltergeist Banner](https://media.ghostsecurity.ai/poltergeist-banner.png)

# Ghost Security Poltergeist

High-performance secret scanner for source code, using [Vectorscan/Hyperscan](https://github.com/VectorCamp/vectorscan) for fast multi-pattern matching. Poltergeist is designed to be easy to use by humans and AI agents alike. For AI agent integration, see [Ghost Security Skills](https://github.com/ghostsecurity/skills).

![Demo](./docs/demo.gif)

## Quick Start

Supports Linux, macOS, and Windows (via Git Bash, MSYS2, or Cygwin).

```bash
curl -sfL https://raw.githubusercontent.com/ghostsecurity/poltergeist/main/scripts/install.sh | bash
```

Alternatively, download a release directly from [GitHub Releases](https://github.com/ghostsecurity/poltergeist/releases).

As a Go library:

```bash
go get github.com/ghostsecurity/poltergeist
```

## Usage

Point Poltergeist at a file or directory and it scans with the built-in rules,
printing redacted matches by default:

```bash
poltergeist /path/to/code
```

Common flags let you change the engine, the output format, and the destination:

```bash
# Emit JSON to a file using the pure-Go engine.
poltergeist -engine go -format json -output findings.json /path/to/code

# Scan with a custom rule file instead of the embedded rules.
poltergeist -rules ./my-rules.yaml /path/to/code
```

Use `-engine` to choose between `auto`, `go`, and `hyperscan`, `-format` to
choose `text`, `json`, or `md`, `-dnr` to show unredacted matches, and
`-low-entropy` to include matches below their entropy threshold. Run
`poltergeist -help` for the full list.

## Building from Source

Building requires Go and the Vectorscan/Hyperscan development library, since the
default engine binds to it through CGO. On Debian and Ubuntu install
`libhyperscan-dev`, and on macOS install `vectorscan` or `hyperscan` with
Homebrew. When the native library is unavailable you can still run the tool with
the pure-Go engine by passing `-engine go`.

```bash
git clone https://github.com/ghostsecurity/poltergeist.git
cd poltergeist
make build
./poltergeist --version
```

## Development

The `Makefile` drives the common workflows, and `make help` lists every target:

```bash
make test        # run the full test suite
make test-rules  # validate the built-in rules against their own test cases
make lint        # run golangci-lint, whose default checks include go vet
make docs        # regenerate docs/rules.md after editing pkg/rules
```

Run `make test` and `make lint` before opening a pull request, and run `make
docs` whenever you change a rule so the generated documentation stays current.
See [CONTRIBUTING](.github/CONTRIBUTING.md) for the full contribution workflow
and [CLAUDE.md](CLAUDE.md) for an architecture-level guide aimed at coding
agents.

## Comprehensive Documentation

Full documentation, tutorials, and video guides at [oss.ghostsecurity.ai](https://oss.ghostsecurity.ai).

## Contributions, Feedback, Feature Requests, and Issues

[Open an Issue](https://github.com/ghostsecurity/poltergeist/issues/new) per the [Contributing](.github/CONTRIBUTING.md) guidelines and [Code of Conduct](.github/CODE_OF_CONDUCT.md)

## Acknowledgments

We'd like to thank the following projects for providing inspiration for Poltergeist and doing tremendous work in the secret scanning space:

- [trufflehog](https://github.com/trufflesecurity/trufflehog)
- [noseyparker](https://github.com/praetorian-inc/noseyparker)
- [kingfisher](https://github.com/mongodb/kingfisher)
- [gitleaks](https://github.com/gitleaks/gitleaks)

## License

This repository is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
