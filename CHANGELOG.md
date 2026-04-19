# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.1] - 2026-04-19

Security-hardening release. No public API changes; existing callers upgrade
without modification. Two verification paths are now stricter, which can
reject previously-accepted tokens and stored hashes that were produced under
inconsistent configuration.

### Security

#### JWT module (`github.com/Jaro-c/authcore/auth/jwt`)
- `VerifyAccessToken` and `RotateTokens` now enforce the `iss` claim against
  `Config.Issuer`, mirroring the existing `aud` check. Previously, a token
  signed by a trusted key was accepted regardless of which service issued it
  — a cross-service key-reuse gap. Tokens with a mismatched issuer now return
  `ErrTokenInvalid`.

#### Password module (`github.com/Jaro-c/authcore/auth/password`)
- `parsePHC` now bounds the `m=` (memory), `t=` (iterations), and `p=`
  (parallelism) parameters read from the stored hash to the same ceilings
  `validateConfig` enforces at construction time. A corrupted or attacker-
  supplied hash of the form `$argon2id$v=19$m=4000000000,…` previously caused
  `argon2.IDKey` to attempt a multi-TiB allocation and crash the process on
  `Verify`; such hashes now return `ErrInvalidHash` before any key derivation.

### Hardening

#### JWT module
- `verifyAccessToken` / `verifyRefreshToken` internal helpers take
  `audience string` (previously `[]string`). The module snapshots
  `Config.Audience[0]` into a private `primaryAudience` field at
  construction, making the verify path immune to post-init mutation of the
  caller's audience slice.

### Fixed

- `module.go` constructor convention comment now lists the actual
  per-module signatures (`jwt.New[T]`, variadic `password.New`, variadic
  `email.New`, `username.New(p)` only) instead of the outdated
  one-size-fits-all form.

---

## [1.0.0] - 2026-03-14

First stable release. The public API is now frozen under the guarantees of
semantic versioning — no breaking changes will be introduced without a major
version bump.

### Added

#### Core (`github.com/Jaro-c/authcore`)
- `New(cfg Config) (*AuthCore, error)` — initialises the library, applies
  defaults, validates configuration, selects logger, and sets up the key manager.
- `DefaultConfig() Config` — returns production-ready defaults
  (`EnableLogs=true`, `Timezone=UTC`, `KeysDir=".authcore"`).
- `Config`, `Logger`, `Keys`, `Provider`, `Module` interfaces — the stable
  extension points for all authentication modules.
- Automatic Ed25519 key-pair generation and persistence on first run
  (`ed25519_private.pem` / `ed25519_public.pem`, mode `0600` / `0644`).
- Automatic HMAC-SHA256 refresh-secret generation (`refresh_secret.key`,
  mode `0600`, 32 bytes / 256 bits of entropy).
- Catch-all `.gitignore` written to `KeysDir` to prevent accidental commits
  of key material.
- Pluggable logger — pass any `authcore.Logger` implementation via
  `Config.Logger`; falls back to a stdlib logger or a silent no-op.
- Timezone-aware `Clock` abstraction (`internal/clock`) for deterministic
  testing without wall-clock sleeps.

#### JWT module (`github.com/Jaro-c/authcore/auth/jwt`)
- `New[T](p Provider, cfg Config) (*JWT[T], error)` — creates the JWT module;
  `T` is the application-specific claims type embedded in access tokens.
- `DefaultConfig() Config` — returns safe defaults
  (`AccessTokenTTL=15m`, `RefreshTokenTTL=24h`, `ClockSkewLeeway=0`).
- `(*JWT[T]).CreateTokens(subject, extra T) (*TokenPair, error)` — issues an
  EdDSA-signed (Ed25519) access + refresh token pair. Subject must be a
  UUID v7 (RFC 9562 §5.7).
- `(*JWT[T]).VerifyAccessToken(token) (*Claims[T], error)` — verifies
  signature, expiry, audience, and token type; returns typed claims.
- `(*JWT[T]).HashRefreshToken(token) string` — returns the HMAC-SHA256 hex
  digest of a refresh token for safe database storage.
- `(*JWT[T]).VerifyRefreshTokenHash(token, storedHash string) bool` —
  constant-time comparison (`crypto/subtle`) of a token against its stored
  hash; prevents timing attacks on database lookups.
- `(*JWT[T]).RotateTokens(refreshToken, extra T) (*TokenPair, error)` —
  verifies a refresh token and issues a fresh token pair with updated claims.
- `Config.ClockSkewLeeway time.Duration` — tolerates small clock drift between
  distributed servers during token verification.
- UUID v7 `jti` generation (RFC 9562 §5.7) — time-ordered, sortable session
  identifiers with 80 bits of cryptographic randomness.
- `kid` JOSE header derived from `SHA-256(publicKey)[:8]` — enables
  zero-downtime key rotation.
- Sentinel errors: `ErrTokenExpired`, `ErrTokenInvalid`, `ErrTokenMalformed`,
  `ErrWrongTokenType`, `ErrInvalidSubject`, `ErrInvalidConfig`.

### Security

- All random material generated with `crypto/rand` (OS entropy source).
- Private key and refresh secret stored with mode `0600` (owner-read only).
- Refresh token never stored in plaintext — only the HMAC-SHA256 digest is
  returned to the caller.
- Algorithm enforcement: `eddsaKeyFunc` rejects any token whose JOSE header
  does not specify `alg=EdDSA`, closing algorithm-confusion attack vectors.

---

## [1.1.1] - 2026-03-15

### Added

#### Password (`auth/password`)
- `(*Password).ValidatePolicy(plaintext string) error` — exposes the built-in
  policy check as a public method for fail-fast validation in HTTP handlers,
  before spending CPU on Argon2id.

---

## [1.1.0] - 2026-03-14

### Added

#### Password module (`github.com/Jaro-c/authcore/auth/password`)
- `New(p Provider, cfg ...Config) (*Password, error)` — creates the password
  module. Config is optional; omitting it applies OWASP-recommended defaults.
- `DefaultConfig() Config` — returns OWASP-recommended Argon2id defaults
  (`Memory=64MiB`, `Iterations=3`, `Parallelism=2`).
- `(*Password).Hash(plaintext string) (string, error)` — validates the
  password against the built-in policy, then derives an Argon2id hash with a
  fresh random salt and returns it in PHC string format.
- `(*Password).Verify(plaintext, phcHash string) (bool, error)` — verifies a
  password against a stored PHC hash using constant-time comparison
  (`crypto/subtle`). Parameters are read from the stored hash, so existing
  hashes remain valid after the module's Config is updated.
- Built-in password policy enforced in `Hash`: 12–64 characters, at least one
  uppercase letter, one lowercase letter, one digit, and one special character.
  Disable via `Config.DisablePolicy` for migration scenarios.
- Sentinel errors: `ErrInvalidConfig`, `ErrInvalidHash`, `ErrWeakPassword`.

### Security

- Updated `golang.org/x/crypto` to v0.45.0, patching three vulnerabilities in
  the `ssh` and `ssh/agent` packages (GO-2025-4116, GO-2025-4134, GO-2025-4135).
  None affected authcore's code paths.
- Raised minimum Go version to 1.26.1, patching five standard library
  vulnerabilities (GO-2026-4599 to GO-2026-4603). None affected authcore's
  code paths.

### Fixed

- Corrected four documentation inaccuracies found during audit:
  - `CreateTokens` docstring referenced non-existent `pair.AccessTokenID` field.
  - `CreateTokens` docstring described `SessionID` as the refresh token's jti;
    it is in fact shared by both the access and refresh tokens.
  - `refreshClaims` internal comment incorrectly stated "no iat claim"; the
    refresh token does include an `iat` claim.
  - `module.go` did not list `auth/password` as an available implementation and
    showed an outdated constructor signature.

---

## [Unreleased]

### Planned

- `auth/apikey` — opaque API-key generation with pluggable store interface.
- `auth/oauth` — OAuth 2.0 / OIDC provider integration.
- Key rotation helpers — zero-downtime rotation utilities.
