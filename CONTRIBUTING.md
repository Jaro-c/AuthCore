# Contributing to authcore

First off, thank you for considering contributing to `authcore`! It's people like you that make it a better tool for everyone.

As a security-focused project, we have a few extra rules to ensure the library remains robust and safe for production use.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Security First

If you find a security vulnerability, **do not open a public issue**. Please follow the reporting process outlined in our [Security Policy](SECURITY.md).

## How Can I Contribute?

### Reporting Bugs

- **Check if the bug has already been reported** by searching the [issues](https://github.com/Jaro-c/authcore/issues).
- If you can't find an open issue addressing the problem, [open a new one](https://github.com/Jaro-c/authcore/issues/new/choose).
- Use the **Bug Report** template.
- Include as much detail as possible: steps to reproduce, Go version, OS, and any relevant logs.

### Suggesting Enhancements

- **Check if the enhancement has already been suggested**.
- [Open a new issue](https://github.com/Jaro-c/authcore/issues/new/choose) using the **Feature Request** template.
- Explain why this enhancement would be useful to most users.

### Pull Requests

1. **Fork the repository** and create your branch from `main`.
2. **Install dependencies**: `go mod download`.
3. **Write tests**: Every new feature or bug fix must include tests. We aim for high coverage, especially for security-critical paths.
4. **Follow Go standards**:
    - Run `go fmt ./...`.
    - Run `go vet ./...`.
    - Use meaningful variable names and document exported functions (following [GoDoc](https://go.dev/doc/effective_go#commentary) style).
5. **Keep it small**: Smaller PRs are easier to review and more likely to be merged.
6. **Update documentation**: If you change public APIs, update the `README.md` and any relevant examples.
7. **Sign your commits**: We prefer signed commits for auditability.

## Development Setup

Requires Go 1.22+.

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/authcore.git
cd authcore

# Run tests
go test -v -race ./...

# Run linting (if you have golangci-lint installed)
golangci-lint run
```

## Pull Request Process

1. Ensure the CI pipeline passes.
2. A maintainer will review your PR within a few days.
3. Once approved, it will be merged into `main`.

Thank you for your contribution!
