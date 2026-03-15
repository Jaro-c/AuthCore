# authcore

[![Go Reference](https://pkg.go.dev/badge/github.com/Jaro-c/authcore.svg)](https://pkg.go.dev/github.com/Jaro-c/authcore)
[![Go Report Card](https://goreportcard.com/badge/github.com/Jaro-c/authcore)](https://goreportcard.com/report/github.com/Jaro-c/authcore)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Jaro-c/authcore/actions/workflows/ci.yml/badge.svg)](https://github.com/Jaro-c/authcore/actions/workflows/ci.yml)

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
- **Automatic key management** — generates, persists, and loads keys on first run
- **Generic custom claims** — embed any struct in access tokens with full type safety
- **Timing-safe comparisons** — `subtle.ConstantTimeCompare` throughout
- **Clock skew tolerance** — configurable leeway for distributed deployments
- **Pluggable logger** — bring slog, zap, zerolog, or any custom backend
- **Testable by design** — injectable clock and `Provider` interface for unit tests
- **Minimal dependencies** — `golang-jwt/jwt/v5` and `golang.org/x/crypto`

---

## Quick Start

```go
package main

import (
    "log"

    "github.com/Jaro-c/authcore"
    "github.com/Jaro-c/authcore/auth/jwt"
)

type UserClaims struct {
    Name string `json:"name"`
    Role string `json:"role"`
}

func main() {
    // 1. Initialise the library once at startup.
    auth, err := authcore.New(authcore.DefaultConfig())
    if err != nil {
        log.Fatal(err)
    }

    // 2. Create the JWT module with your custom claims type.
    jwtMod, err := jwt.New[UserClaims](auth, jwt.DefaultConfig())
    if err != nil {
        log.Fatal(err)
    }

    // 3. Issue a token pair on login.
    pair, err := jwtMod.CreateTokens(userID, UserClaims{Name: "Ana", Role: "admin"})
    if err != nil {
        log.Fatal(err)
    }

    // Send pair.AccessToken  → Authorization: Bearer header
    // Send pair.RefreshToken → secure httpOnly cookie
    // Store pair.RefreshTokenHash in your database (never the raw token)
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

### Setup

```go
auth, err := authcore.New(authcore.DefaultConfig())
if err != nil {
    log.Fatal(err)
}

pwdMod, err := password.New(auth, password.DefaultConfig())
if err != nil {
    log.Fatal(err)
}
```

`password.DefaultConfig()` values (OWASP Argon2id recommendations):

| Field | Default | Notes |
|---|---|---|
| `Memory` | `65536` (64 MiB) | KiB allocated per hash |
| `Iterations` | `3` | Passes over memory |
| `Parallelism` | `2` | Threads; match guaranteed CPU cores |

---

### Hashing a password

```go
hash, err := pwdMod.Hash(userPassword)
if err != nil {
    log.Fatal(err)
}
// Store hash in your database — never store the plaintext.
db.StorePasswordHash(userID, hash)
```

Each call generates a fresh random salt, so two hashes of the same password
are different strings but both verify correctly.

The returned string is a self-describing **PHC format** value:

```
$argon2id$v=19$m=65536,t=3,p=2$<base64-salt>$<base64-hash>
```

All Argon2id parameters are embedded in the string, so stored hashes remain
valid even if you tune the work parameters later.

---

### Verifying a password

```go
ok, err := pwdMod.Verify(submittedPassword, storedHash)
switch {
case errors.Is(err, password.ErrInvalidHash):
    // 500 — hash stored in the database is malformed
case err != nil:
    // 500 — unexpected error
case !ok:
    // 401 — wrong password
}
```

The comparison is performed in **constant time** (`crypto/subtle`) to prevent
timing attacks. Parameters are always read from `storedHash`, not from the
module's current `Config`.

---

### Tuning work parameters

Increase the work factor on more capable hardware to keep hashing time around
200–500 ms per operation:

```go
cfg := password.DefaultConfig()
cfg.Memory      = 128 * 1024  // 128 MiB — for a dedicated auth server
cfg.Iterations  = 4
cfg.Parallelism = 4           // match your guaranteed CPU core count

pwdMod, err := password.New(auth, cfg)
```

> **Old hashes stay valid.** Parameters are stored inside the hash string.
> Changing `Config` only affects newly created hashes — existing users are
> verified against the parameters that were active when their hash was created.

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
│   └── password/        # Argon2id password hashing
│
└── examples/
    └── basic/           # Runnable end-to-end example
```

| Import path | Visibility | Purpose |
|---|---|---|
| `github.com/Jaro-c/authcore` | public | Core types and entry point |
| `…/auth/jwt` | public | JWT module |
| `…/auth/password` | public | Argon2id password hashing module |
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

Always use `errors.Is` for error inspection — errors may be wrapped:

```go
claims, err := jwtMod.VerifyAccessToken(token)
if errors.Is(err, jwt.ErrTokenExpired) {
    // prompt the client to refresh
}
```

---

## Roadmap

- [x] Core library — key management, logger, clock, Provider interface
- [x] `auth/jwt` — EdDSA token issuance, verification, rotation, timing-safe hash
- [x] `auth/password` — Argon2id password hashing with PHC format
- [ ] `auth/apikey` — opaque key generation with pluggable store interface *(future)*
- [ ] `auth/oauth` — OAuth 2.0 / OIDC provider integration *(future)*
- [ ] Key rotation helpers — zero-downtime rotation via `kid` header *(future)*

---

## Contributing

Contributions are welcome! Please read the [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) before opening a pull request.

## Security

To report a vulnerability, please follow the [Security Policy](SECURITY.md).
Do not open a public issue for security bugs.

## License

Released under the [MIT License](LICENSE).
