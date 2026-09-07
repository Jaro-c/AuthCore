# Configuration & logging

## The principle

authcore is built in two layers: a cryptographic layer that is closed, and a
policy layer that is open with secure defaults. The split is decided by one
question: if a user picks the worst legal value for this field, what
breaks?

- **Their security breaks** - the field is closed. The library ships a
  single value and the caller cannot weaken it.
- **Only their own product rule breaks** - the field is open, with today's
  value as the default. The caller can opt in to a stricter or looser
  setting without weakening the security floor the library enforces.

### What is open and what is closed, per module

| Module | Open (configurable, secure default) | Closed (security control) |
|---|---|---|
| `password` | Work factor: `Memory`, `Iterations`, `Parallelism` · Policy: `MinLength`, `MaxLength`, `RequireUpper`, `RequireLower`, `RequireDigit`, `RequireSymbol` | Argon2id algorithm · 16-byte salt · 32-byte key · PHC output format · constant-time compare · Unicode NFC normalisation |
| `email` | `RejectPlusAddressing` | RFC 5321/5322 parse and normalisation · IDN punycode conversion |
| `username` | `MinLength`, `MaxLength`, `ExtraReservedNames`, `AllowReservedNames` | Character set `[a-z0-9_-]` · lowercase + trim normalisation · "must start and end with a letter or digit" rule · "no consecutive specials" rule |

A field listed under "closed" cannot be configured: trying to do so would
either be rejected at compile time or be a deliberate error in the code.
The closed set is the homoglyph control, the KDF choice, and the comparison
discipline - every one of which has a known attack if it is weakened.

## Config

```go
type Config struct {
    EnableLogs bool             // emit log output; default true via DefaultConfig()
    Timezone   *time.Location   // time zone for all operations; default time.UTC
    Logger     authcore.Logger   // custom logger (slog, zap, zerolog, …); overrides EnableLogs
    KeysDir    string            // key storage directory; default ".authcore"; ignored when KeyStore is set
    KeyStore   authcore.KeyStore // optional: source keys from a secret manager / env / KMS instead of disk
}
```

`KeyStore` lets you supply key material instead of using the disk under
`KeysDir` — see [Key management](key-management.md) (`NewKeyStoreFromKeys`,
`NewKeyStoreFromPEM`). Leave it nil for the zero-config disk default.

Always start from `DefaultConfig()` and override only what you need:

```go
cfg := authcore.DefaultConfig()
cfg.EnableLogs = false                    // silence output in tests
cfg.Logger     = slog.Default()           // use your application logger
cfg.KeysDir    = "/run/secrets/authcore"  // absolute path in containers
```

> **Note on `EnableLogs`:** Go cannot distinguish `EnableLogs = false` from a
> zero-value `Config{}`. Start from `DefaultConfig()` to get `EnableLogs = true`,
> then set it to `false` to explicitly opt out.

## Custom logger

Implement the `Logger` interface to route authcore output through your existing
log pipeline:

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
