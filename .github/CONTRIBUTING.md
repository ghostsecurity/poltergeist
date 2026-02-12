# Contributing to Poltergeist

Thanks for your interest in contributing to poltergeist! Here's how to get started.

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b my-feature`)
3. Make your changes
4. Submit a pull request

## Development Setup

Prerequisites: Go and Make.

```bash
git clone https://github.com/<your-fork>/poltergeist.git
cd poltergeist
make build
```

## Running Tests & Linting

```bash
make test
make lint
```

Both must pass before submitting a PR.

## Pull Requests

- Keep PRs focused on a single change
- Write clear, descriptive commit messages
- Add tests for new functionality
- Ensure `make test` and `make lint` pass

## Reporting Bugs

Open a [GitHub Issue](https://github.com/ghostsecurity/poltergeist/issues) with:

- Steps to reproduce
- Expected vs actual behavior
- Poltergeist version (`poltergeist --version`)
- OS and environment details

## Suggesting Features

Open a [GitHub Issue](https://github.com/ghostsecurity/poltergeist/issues) describing:

- The use case or problem
- Your proposed solution (if any)

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](../LICENSE).
