# authcore

[![Go Reference](https://pkg.go.dev/badge/github.com/Jaro-c/authcore.svg)](https://pkg.go.dev/github.com/Jaro-c/authcore)
[![Go Report Card](https://goreportcard.com/badge/github.com/Jaro-c/authcore)](https://goreportcard.com/report/github.com/Jaro-c/authcore)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Jaro-c/authcore/actions/workflows/ci.yml/badge.svg)](https://github.com/Jaro-c/authcore/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Jaro-c/authcore/branch/main/graph/badge.svg)](https://codecov.io/gh/Jaro-c/authcore)
[![CodeQL](https://github.com/Jaro-c/authcore/actions/workflows/codeql.yml/badge.svg)](https://github.com/Jaro-c/authcore/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Jaro-c/authcore/badge)](https://scorecard.dev/viewer/?uri=github.com/Jaro-c/authcore)

**A modular, production-ready authentication library for Go 1.26+.**

authcore gives you secure token issuance, automatic key management, and a clean plugin architecture — so you can focus on your application instead of cryptographic plumbing.

```
go get github.com/Jaro-c/authcore
```

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [JWT Authentication](#jwt-authentication)
  - [Setup](#setup)
  - [Login — creating a token pair](#login--creating-a-token-pair)
  - [Authenticating requests](#authenticating-requests)
  - [Rotating tokens](#rotating-tokens)
  - [Clock skew tolerance](#clock-skew-tolerance)
- [Password Hashing](#password-hashing)
  - [Setup](#setup-1)
  - [Hashing a password](#hashing-a-password)
  - [Verifying a password](#verifying-a-password)
  - [Tuning work parameters](#tuning-work-parameters)
- [Email Validation](#email-validation)
  - [Setup](#setup-2)
  - [Validating and normalizing](#validating-and-normalizing)
  - [Verifying a domain can receive email](#verifying-a-domain-can-receive-email)
- [Username Validation](#username-validation)
  - [Setup](#setup-3)
  - [Validating and normalizing](#validating-and-normalizing-1)
- [Key Management](#key-management)
- [Configuration](#configuration)
- [Custom Logger](#custom-logger)
- [Project Layout](#project-layout)
- [Writing a Module](#writing-a-module)
- [Error Handling](#error-handling)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

## Features

- **EdDSA / Ed25519 token signing** — fast, constant-time, no padding-oracle risk
- **Dual-token model** — short-lived access tokens + long-lived refresh tokens
- **Argon2id password hashing** — memory-hard, GPU/ASIC-resistant, PHC format
- **Email validation & normalization** — RFC 5321/5322 compliance, optional DNS MX verification with cache
- **Username validation & normalization** — character rules, consecutive-special detection, fixed reserved name blocklist
- **Automatic key management** — generates, persists, and loads keys on first run
- **Generic custom claims** — embed any struct in access tokens with full type safety
- **Timing-safe comparisons** — `subtle.ConstantTimeCompare` throughout
- **Clock skew tolerance** — configurable leeway for distributed deployments
- **Pluggable logger** — bring slog, zap, zerolog, or any custom backend
- **Testable by design** — injectable clock and `Provider` interface for unit tests
- **Minimal dependencies** — `golang-jwt/jwt/v5`, `golang.org/x/crypto`, `golang.org/x/sync`

---

## Quick Start

```go
package main

import (
    "log"

    "github.com/Jaro-c/authcore"
    "github.com/Jaro-c/authcore/auth/jwt"
    "github.com/Jaro-c/authcore/auth/password"
)

type UserClaims struct {
    Name string `json:"name"`
    Role string `json:"role"`
}

func main() {
    // 1. One-time setup at startup.
    auth, err := authcore.New(authcore.DefaultConfig())
    if err != nil {
        log.Fatal(err)
    }

    // 2. Password hashing — zero config, secure defaults.
    pwdMod, err := password.New(auth)
    if err != nil {
        log.Fatal(err)
    }

    // 3. JWT tokens — configure issuer/audience for your service.
    jwtMod, err := jwt.New[UserClaims](auth, jwt.DefaultConfig())
    if err != nil {
        log.Fatal(err)
    }

    // Registration: hash and store — never store the plaintext.
    hash, _ := pwdMod.Hash("user-chosen-password")
    _ = hash // → db.StorePasswordHash(userID, hash)

    // Login: verify password, then issue a token pair.
    ok, _ := pwdMod.Verify("user-submitted-password", hash)
    if !ok {
        log.Fatal("wrong password")
    }

    pair, _ := jwtMod.CreateTokens(userID, UserClaims{Name: "Ana", Role: "admin"})
    // pair.AccessToken      → Authorization: Bearer header
    // pair.RefreshToken     → secure httpOnly cookie
    // pair.RefreshTokenHash → store in your database (never the raw token)
    _ = pair
}
```

---

## JWT Authentication

### Setup

```go
cfg := jwt.DefaultConfig()
cfg.Issuer   = "https://auth.example.com"
cfg.Audience = []string{"https://api.example.com"}

// Optional: tolerate up to 30 s of clock drift between servers.
cfg.ClockSkewLeeway = 30 * time.Second

jwtMod, err := jwt.New[UserClaims](auth, cfg)
```

`jwt.DefaultConfig()` values:

| Field | Default |
|---|---|
| `AccessTokenTTL` | 15 minutes |
| `RefreshTokenTTL` | 24 hours |
| `Issuer` | `"github.com/Jaro-c/authcore"` |
| `Audience` | `["github.com/Jaro-c/authcore"]` |
| `ClockSkewLeeway` | 0 (no leeway) |

---

### Login — creating a token pair

```go
// subject must be a UUID v7 (RFC 9562 §5.7).
pair, err := jwtMod.CreateTokens(userID, UserClaims{Name: "Ana", Role: "admin"})
if err != nil {
    // jwt.ErrInvalidSubject — subject is not a valid UUID v7
}

pair.AccessToken            // short-lived JWT for API requests
pair.AccessTokenExpiresAt   // time.Time — tell the client when to refresh
pair.RefreshToken           // long-lived JWT for token rotation
pair.RefreshTokenExpiresAt  // time.Time — when the user must log in again
pair.RefreshTokenHash       // HMAC-SHA256 hex digest — store this in your DB
pair.SessionID              // UUID v7 jti shared by both tokens — use as session PK
```

> **Never store the raw refresh token.** Store only `RefreshTokenHash`.

---

### Authenticating requests

```go
claims, err := jwtMod.VerifyAccessToken(tokenFromHeader)
switch {
case errors.Is(err, jwt.ErrTokenExpired):
    // 401 — client should refresh
case errors.Is(err, jwt.ErrTokenInvalid):
    // 401 — tampered or wrong key
case errors.Is(err, jwt.ErrTokenMalformed):
    // 400 — not a JWT at all
case err != nil:
    // 401 — catch-all
}

fmt.Println(claims.Subject)    // UUID v7 user ID
fmt.Println(claims.Extra.Role) // "admin" — your custom claims
fmt.Println(claims.ExpiresAt)  // time.Time
```

---

### Rotating tokens

The recommended pattern — verify the hash **before** calling `RotateTokens` to prevent
token-reuse attacks even if your database is compromised:

```go
// 1. Compute the hash of the token the client presented.
incoming := jwtMod.HashRefreshToken(clientToken)

// 2. Look it up in your database.
session, err := db.FindSessionByHash(incoming)
if err != nil {
    return http.StatusUnauthorized
}

// 3. Use timing-safe comparison to verify the hash matches.
//    This prevents timing attacks on the lookup result.
if !jwtMod.VerifyRefreshTokenHash(clientToken, session.RefreshTokenHash) {
    return http.StatusUnauthorized
}

// 4. Rotate — authcore verifies the token's signature and expiry.
freshClaims := UserClaims{Name: session.UserName, Role: session.UserRole}
newPair, err := jwtMod.RotateTokens(clientToken, freshClaims)
if err != nil {
    return http.StatusUnauthorized
}

// 5. Atomically replace the old hash in your database.
db.ReplaceRefreshHash(session.ID, newPair.RefreshTokenHash)

// 6. Send the new tokens to the client.
```

---

### Clock skew tolerance

In distributed systems, server clocks may drift by a few seconds. Set `ClockSkewLeeway`
to accept tokens that expired within that window:

```go
cfg.ClockSkewLeeway = 30 * time.Second
```

The leeway applies to both access and refresh token verification.
Keep it small — large values reduce the security margin of short-lived tokens.

---

## Password Hashing

No boilerplate. No algorithm choices. Just secure password hashing that works.

### Setup

```go
auth, err := authcore.New(authcore.DefaultConfig())

// Zero-config — OWASP-recommended Argon2id defaults applied automatically.
pwdMod, err := password.New(auth)
```

That's it. No config required.

> **Why Argon2id?** It's memory-hard: an attacker must allocate ~64 MiB of RAM
> *per attempt*, making GPU and ASIC brute-force attacks prohibitively expensive.
> bcrypt does not have this property.

---

### Hashing a password

```go
hash, err := pwdMod.Hash(userPassword)
switch {
case errors.Is(err, password.ErrWeakPassword):
    // 400 — tell the user exactly what's missing (message is descriptive)
case err != nil:
    // 500 — unexpected error
}
// Store hash in your database. Never store the plaintext.
db.StorePasswordHash(userID, hash)
```

`Hash` validates the password **before** spending CPU on hashing:

| Rule | Requirement |
|---|---|
| Length | 12 – 64 characters |
| Uppercase | At least one (`A`–`Z`, Unicode-aware) |
| Lowercase | At least one (`a`–`z`, Unicode-aware) |
| Digit | At least one (`0`–`9`) |
| Special | At least one (anything that is not a letter or digit) |

Each call also generates a **fresh random salt**, so two hashes of the same
password are always different strings — but both verify correctly.

The stored string is fully self-describing (**PHC format**):

```
$argon2id$v=19$m=65536,t=3,p=2$<base64-salt>$<base64-hash>
```

---

### Verifying a password

```go
ok, err := pwdMod.Verify(submittedPassword, storedHash)
switch {
case errors.Is(err, password.ErrInvalidHash):
    // 500 — hash in the database is malformed
case !ok:
    // 401 — wrong password
}
```

Comparison is **constant-time** (`crypto/subtle`) — timing attacks are not
possible. Parameters are always read from the stored hash, never from the
current module config.

---

### Tuning work parameters (optional)

The defaults are sized for 2 vCPUs / 4 GiB RAM. On more powerful hardware,
crank them up — a hash should take roughly 200–500 ms:

```go
pwdMod, err := password.New(auth, password.Config{
    Memory:      128 * 1024, // 128 MiB
    Iterations:  4,
    Parallelism: 4,          // match your guaranteed CPU core count
})
```

| Field | Default | Minimum |
|---|---|---|
| `Memory` | `65536` (64 MiB) | `8192` (8 MiB) |
| `Iterations` | `3` | `1` |
| `Parallelism` | `2` | `1` |

> **Old hashes stay valid.** All parameters live inside the hash string itself.
> Changing the config only affects *new* hashes — existing users keep working.

---

## Email Validation

### Setup

```go
emailMod, err := email.New(auth)
if err != nil {
    log.Fatal(err)
}
defer emailMod.Close() // stops the background cache eviction goroutine
```

---

### Validating and normalizing

Always call `ValidateAndNormalize` instead of validating and normalizing separately.
It lowercases, trims whitespace, and validates in a single call — ensuring the value
you store is always in canonical form:

```go
normalized, err := emailMod.ValidateAndNormalize(req.Email)
switch {
case errors.Is(err, email.ErrInvalidEmail):
    // 400 — tell the user exactly what failed (message is descriptive)
    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
    return
case err != nil:
    // 500 — unexpected error
}
// Store normalized — always lowercase, trimmed.
db.StoreUser(normalized, ...)
```

Validation rules (RFC 5321 / RFC 5322):

| Rule | Requirement |
|---|---|
| Total length | 1 – 254 characters |
| Format | One `@` separating a non-empty local part and domain |
| Local part | ≤ 64 characters |
| Domain | At least one dot; no leading, trailing, or consecutive dots |
| Domain labels | 1 – 63 characters each |

> **Always normalize before storing and before querying.** This ensures consistent
> lookup — `User@EXAMPLE.COM` and `user@example.com` are the same address.

---

### Verifying a domain can receive email

`VerifyDomain` performs an optional DNS MX lookup to confirm the domain is
configured to receive email. Call it after `ValidateAndNormalize` when you
want to reject obviously fake domains before sending a verification email.

Results are cached per domain (default 5 minutes) and DNS lookups for the same
domain are deduplicated via `singleflight` — safe for high-concurrency workloads.

```go
ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
defer cancel()

err = emailMod.VerifyDomain(ctx, normalized)
switch {
case errors.Is(err, email.ErrDomainNoMX):
    // 400 — domain exists but cannot receive email
    c.JSON(400, map[string]string{"error": "email domain cannot receive messages"})
    return
case errors.Is(err, email.ErrDomainUnresolvable):
    // DNS lookup failed — do NOT block the user; log and continue
    log.Warn("DNS check unavailable: %v", err)
}
```

> **`ErrDomainUnresolvable` is a soft failure.** DNS can be temporarily
> unavailable due to network issues unrelated to the user's input. Never
> block a registration on this error — log it and proceed.

---

## Username Validation

### Setup

```go
userMod, err := username.New(auth)
if err != nil {
    log.Fatal(err)
}
```

---

### Validating and normalizing

Always call `ValidateAndNormalize` — it lowercases, trims whitespace, and validates in a
single call, ensuring the value you store is always in canonical form:

```go
normalized, err := userMod.ValidateAndNormalize(req.Username)
if err != nil {
    // errors.Unwrap(err).Error() contains the specific rule that failed.
    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
    return
}
db.StoreUser(normalized, ...) // always lowercase, trimmed, validated
```

Validation rules:

| Rule | Requirement |
|---|---|
| Length | 3 – 32 characters (fixed) |
| Allowed characters | `[a-z0-9_-]` only |
| First character | Letter or digit (not `_` or `-`) |
| Last character | Letter or digit (not `_` or `-`) |
| Consecutive specials | `__`, `--`, `_-`, `-_` are rejected |
| Reserved names | Built-in blocklist (fixed) |

> **Always normalize before storing and before querying.** `Alice123` and `alice123`
> are the same username — store only the canonical (normalized) form.

---

## Key Management

On first run authcore creates `KeysDir` (default `.authcore`) and generates:

| File | Format | Mode | Purpose |
|---|---|---|---|
| `ed25519_private.pem` | PKCS#8 PEM | `0600` | Signing key |
| `ed25519_public.pem` | PKIX PEM | `0644` | Verification key |
| `refresh_secret.key` | 32-byte hex | `0600` | HMAC-SHA256 key for refresh token hashing |
| `.gitignore` | `*` | `0600` | Prevents accidental commits |

On subsequent starts the files are loaded and the key pair is validated for consistency.
If only one PEM file is present, `New()` returns `ErrKeyManager` — delete both to regenerate.

**In containers or CI**, point `KeysDir` at a mounted secrets volume:

```go
cfg := authcore.DefaultConfig()
cfg.KeysDir = os.Getenv("AUTHCORE_KEYS_DIR") // e.g. /run/secrets/authcore
auth, err := authcore.New(cfg)
```

The `KeyID()` accessor returns a 16-character hex digest derived from the public key.
It is embedded in every token's `kid` JOSE header, enabling zero-downtime key rotation.

---

## Configuration

```go
type Config struct {
    EnableLogs bool             // emit log output; default true via DefaultConfig()
    Timezone   *time.Location   // time zone for all operations; default time.UTC
    Logger     authcore.Logger  // custom logger (slog, zap, zerolog, …); overrides EnableLogs
    KeysDir    string           // key storage directory; default ".authcore"
}
```

Always start from `DefaultConfig()` and override only what you need:

```go
cfg := authcore.DefaultConfig()
cfg.EnableLogs = false                    // silence output in tests
cfg.Logger     = slog.Default()           // use your application logger
cfg.KeysDir    = "/run/secrets/authcore"  // absolute path in containers
```

> **Note on `EnableLogs`:** Go cannot distinguish `EnableLogs = false` from a zero-value
> `Config{}`. Start from `DefaultConfig()` to get `EnableLogs = true`, then set it to
> `false` to explicitly opt out.

---

## Custom Logger

Implement the `Logger` interface to route authcore output through your existing log pipeline:

```go
type Logger interface {
    Debug(msg string, args ...any)
    Info(msg string, args ...any)
    Warn(msg string, args ...any)
    Error(msg string, args ...any)
}
```

`*slog.Logger` satisfies this interface directly:

```go
cfg := authcore.DefaultConfig()
cfg.Logger = slog.Default() // or slog.New(yourHandler)
```

When `Config.Logger` is non-nil it takes precedence over `EnableLogs`.

---

## Project Layout

```
authcore/
├── authcore.go          # New() · AuthCore struct · compile-time interface assertions
├── config.go            # Config · DefaultConfig()
├── logger.go            # Logger interface · stdlib and noop implementations
├── module.go            # Keys · Provider · Module interfaces
├── errors.go            # Sentinel errors
│
├── internal/
│   ├── clock/           # Timezone-aware Clock — injected for deterministic tests
│   └── keymanager/      # Ed25519 + HMAC key generation, persistence, validation
│
├── auth/
│   ├── jwt/             # JSON Web Token authentication (EdDSA / Ed25519)
│   ├── password/        # Argon2id password hashing
│   ├── email/           # Email validation, normalization, DNS MX verification
│   └── username/        # Username validation, normalization, reserved name blocklist
│
└── examples/
    ├── basic/           # authcore initialisation strategies
    ├── jwt/             # JWT: create, verify, rotate
    ├── password/        # Password: policy, hash, verify
    ├── email/           # Email: validate, normalize, DNS MX verification
    ├── username/        # Username: validate, normalize, reserved names
    ├── fiber/           # Full auth API with Fiber v3 (separate module)
    └── gin/             # Full auth API with Gin (separate module)
```

| Import path | Visibility | Purpose |
|---|---|---|
| Import path | Visibility | Purpose |
|---|---|---|
| `github.com/Jaro-c/authcore` | public | Core types and entry point |
| `…/auth/jwt` | public | JWT module |
| `…/auth/password` | public | Argon2id password hashing module |
| `…/auth/email` | public | Email validation, normalization, MX verification |
| `…/auth/username` | public | Username validation, normalization, reserved names |
| `…/internal/clock` | internal | Shared time abstraction |
| `…/internal/keymanager` | internal | Key generation and persistence |

---

## Writing a Module

Modules depend on `authcore.Provider` — not the concrete `*AuthCore` — so they remain
independently testable without touching the filesystem or generating real keys.

```go
// Provider is the narrow interface that *AuthCore satisfies.
type Provider interface {
    Config() Config  // shared configuration
    Logger() Logger  // shared logger sink
    Keys()   Keys    // Ed25519 keys + HMAC secret
}

// Module is the marker interface every sub-module must implement.
type Module interface {
    Name() string // stable, lowercase identifier e.g. "jwt"
}
```

Minimal module skeleton:

```go
package mypkg

import "github.com/Jaro-c/authcore"

type MyModule struct {
    log authcore.Logger
    // ...
}

func New(p authcore.Provider, cfg Config) (*MyModule, error) {
    return &MyModule{log: p.Logger()}, nil
}

func (m *MyModule) Name() string { return "mypkg" }
```

In tests, inject a stub `Provider` that returns fixed keys — no disk I/O required.

---

## Error Handling

### authcore package

| Error | When |
|---|---|
| `authcore.ErrInvalidConfig` | `Config` validation failed |
| `authcore.ErrInvalidTimezone` | `Config.Timezone` is nil |
| `authcore.ErrKeyManager` | key generation or loading failed |

### auth/jwt package

| Error | When |
|---|---|
| `jwt.ErrInvalidConfig` | `jwt.Config` validation failed |
| `jwt.ErrTokenExpired` | `exp` claim is in the past (beyond leeway) |
| `jwt.ErrTokenInvalid` | signature invalid or unsupported algorithm |
| `jwt.ErrTokenMalformed` | not a valid three-part JWT string |
| `jwt.ErrWrongTokenType` | access token passed where refresh expected, or vice-versa |
| `jwt.ErrInvalidSubject` | subject passed to `CreateTokens` is not a UUID v7 |

### auth/password package

| Error | When |
|---|---|
| `password.ErrInvalidConfig` | `password.Config` validation failed |
| `password.ErrInvalidHash` | stored hash is malformed or not Argon2id PHC format |
| `password.ErrWeakPassword` | plaintext does not meet the built-in policy |

### auth/email package

| Error | Client-safe? | When |
|---|---|---|
| `email.ErrInvalidEmail` | ✓ Yes | Address fails RFC 5321/5322 validation; `errors.Unwrap` gives the specific rule |
| `email.ErrDomainNoMX` | ✓ Yes | Domain exists but has no MX records (cannot receive email) |
| `email.ErrDomainUnresolvable` | ✗ No | DNS lookup failed; treat as soft failure, do not block the user |

### auth/username package

| Error | Client-safe? | When |
|---|---|---|
| `username.ErrInvalidUsername` | ✓ Yes | Username fails a validation rule; `errors.Unwrap` gives the specific rule |
| `username.ErrInvalidConfig` | ✗ No | `username.Config` validation failed (startup error, treat as 500) |

Always use `errors.Is` for error inspection — errors may be wrapped:

```go
claims, err := jwtMod.VerifyAccessToken(token)
if errors.Is(err, jwt.ErrTokenExpired) {
    // prompt the client to refresh
}
```

---

## FAQ

**My access token fails verification in a distributed system — is clock skew the issue?**

Yes. Different servers may have clocks that drift a few seconds apart, causing
`ErrTokenExpired` on a brand-new token. Set `ClockSkewLeeway` in your JWT config:

```go
cfg := jwt.DefaultConfig()
cfg.ClockSkewLeeway = 5 * time.Second
```

---

**I'm getting `ErrKeyManager` on startup. What went wrong?**

authcore could not read or create its key files. Check that:
1. `KeysDir` (default `.authcore`) is writable by the process.
2. The directory is not a read-only filesystem (common in some container setups).
3. Existing key files are not corrupted — delete `.authcore` and let authcore regenerate them.

---

**Can I verify tokens issued before I rotated my signing key?**

Yes. authcore embeds the `kid` (key ID) in every token header. When you add a new
key pair, keep the old public key in the key store under its original `kid`. The
verifier will select the right key automatically. See the
[Key Management](#key-management) section for the rotation workflow.

---

**My existing password hashes were created with a different library. Can I migrate?**

Yes, as long as the hashes are in PHC string format (`$argon2id$v=19$...`).
`Verify` reads all parameters from the stored hash, so it works regardless of which
library produced it. For hashes in a legacy format, validate the password at your
application layer before calling `Hash`, then re-hash on the user's next successful login.

---

**The `Hash` call is slower than expected in tests. Is that normal?**

Yes — Argon2id deliberately takes ~100–300 ms and allocates 64 MiB of RAM per call.
In tests, use a low-cost config to avoid slow suites:

```go
pwd, _ := password.New(auth, password.Config{
    Memory:      8 * 1024, // minimum allowed (8 MiB)
    Iterations:  1,
    Parallelism: 1,
})
```

---

## Coverage

[![Sunburst](https://codecov.io/github/Jaro-c/AuthCore/graphs/sunburst.svg?token=YXE6LDJFCQ)](https://app.codecov.io/gh/Jaro-c/AuthCore)

Each ring is a directory; each slice is a file. Greener wedges are better covered. Click through for the full per-line report on Codecov.

---

## Roadmap

- [x] Core library — key management, logger, clock, Provider interface
- [x] `auth/jwt` — EdDSA token issuance, verification, rotation, timing-safe hash
- [x] `auth/password` — Argon2id password hashing with PHC format
- [x] `auth/email` — RFC 5321/5322 validation, normalization, DNS MX verification with cache
- [x] `auth/username` — validation, normalization, reserved name blocklist, configurable length limits
- [ ] `auth/apikey` — opaque key generation with pluggable store interface *(future)*
- [ ] `auth/oauth` — OAuth 2.0 / OIDC provider integration *(future)*
- [ ] Key rotation helpers — zero-downtime rotation via `kid` header *(future)*

---

## API Stability

authcore follows [Semantic Versioning](https://semver.org).

- **`v0.x` (current)** — the public API may introduce breaking changes between minor releases while the library matures. Pin your dependency with `go.sum` and review release notes before upgrading.
- **`v1.0.0` (future)** — once published, the public API is covered by compatibility guarantees. Breaking changes will only ship in a new major version.

Internal packages (`internal/…`) carry no compatibility guarantees at any version and must not be imported from outside the module.

---

## Contributing

Contributions are welcome! Please read the [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) before opening a pull request.

## Security

To report a vulnerability, please follow the [Security Policy](SECURITY.md).
Do not open a public issue for security bugs.

## License

Released under the [MIT License](LICENSE).
