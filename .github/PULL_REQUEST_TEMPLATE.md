## Description

Summarize the change and link the related issue.

Fixes # (issue)

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change
- [ ] Security fix
- [ ] Documentation update

## Security impact

Does this change affect cryptographic operations, token handling, key management, or any security boundary?

- [ ] No security impact
- [ ] Yes — describe below

<!-- If yes, explain: what was the risk, how is it addressed, and what threat model was considered. -->

## Testing

- [ ] `go test -race ./...` passes locally
- [ ] New tests added for this change
- [ ] Existing tests updated where necessary
- [ ] Tested with the race detector (`-race`)

## Checklist

- [ ] Code follows the project style (`go fmt`, `go vet`, `golangci-lint`)
- [ ] All exported symbols have godoc comments
- [ ] `README.md` updated if public API changed
- [ ] No sensitive data (keys, tokens, secrets) is logged or exposed in tests
- [ ] Dependent changes merged and published upstream (if any)
