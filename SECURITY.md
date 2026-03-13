# Security Policy

## Supported Versions

Only the latest published version of authcore receives security fixes.

| Version | Supported |
|---------|-----------|
| latest  | ✅        |
| < latest| ❌        |

Once the library reaches a stable `v1.0.0`, a formal long-term support window will be defined here.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues via [GitHub private vulnerability reporting](https://github.com/Jaro-c/authcore/security/advisories/new).
This keeps the details confidential until a patch is released.

Include as much of the following as possible:

- A clear description of the vulnerability and its potential impact.
- Steps to reproduce or a minimal proof-of-concept (PoC).
- The affected version(s) — output of `go list -m github.com/Jaro-c/authcore`.
- Any known mitigations or workarounds.

You will receive an acknowledgement within **72 hours**.
We aim to release a patch within **14 days** for confirmed critical issues and **30 days** for non-critical ones.
Reporters will be credited in the release notes unless you prefer to remain anonymous.

## Scope

This policy covers the `github.com/Jaro-c/authcore` module and all sub-packages published under this repository:

- `auth/jwt`
- `auth/apikey` *(planned)*
- `auth/oauth` *(planned)*

Third-party dependencies are out of scope — please report those issues to their respective maintainers.

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter submits the vulnerability privately.
2. Maintainers confirm and reproduce the issue within 72 hours.
3. A fix is developed in a private branch.
4. A patched release is published.
5. A public security advisory is opened with full details.

## Security Best Practices for Users

- Always use the latest published version of authcore.
- Pin your dependency with `go.sum` and verify checksums via the Go module proxy.
- Never store raw refresh tokens — always store only the `RefreshTokenHash` value.
- Protect your `KeysDir` (default `.authcore`) with filesystem permissions; never commit it.
- Set `ClockSkewLeeway` to the minimum value needed for your deployment — larger windows reduce the security margin of short-lived tokens.
