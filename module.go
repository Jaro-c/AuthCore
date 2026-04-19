package authcore

import "crypto/ed25519"

// Keys provides read-only access to authcore's managed cryptographic material.
//
// The concrete implementation is *keymanager.KeyManager (internal).
// Sub-modules receive Keys through the Provider interface and must not
// cache or copy the raw key bytes — always call the accessor methods.
type Keys interface {
	// PrivateKey returns the Ed25519 private key used for signing tokens.
	// The caller must not modify the returned slice.
	PrivateKey() ed25519.PrivateKey

	// PublicKey returns the Ed25519 public key used for signature verification.
	// The caller must not modify the returned slice.
	PublicKey() ed25519.PublicKey

	// RefreshSecret returns the 32-byte HMAC-SHA256 key used to hash refresh
	// tokens before they are stored in a database.
	// The caller must not modify the returned slice.
	RefreshSecret() []byte

	// KeyID returns the stable identifier for the current signing key.
	// It is derived from the public key and embedded in the "kid" JOSE header
	// of every issued token so that verifiers can select the correct key when
	// multiple keys are in circulation (e.g. during key rotation).
	KeyID() string
}

// Provider is the narrow interface that *AuthCore satisfies.
//
// Sub-modules must accept a Provider rather than *AuthCore directly.
// This decouples each module from the concrete library type, which has two
// important consequences:
//
//  1. Testability — unit tests can inject a stub Provider without constructing
//     a real AuthCore or touching the file system / network.
//
//  2. Stability — if AuthCore gains new methods in a future release, existing
//     module code is unaffected because it only depends on the methods below.
//
// Guaranteed implementation: *AuthCore.
type Provider interface {
	// Config returns a copy of the active library configuration.
	Config() Config

	// Logger returns the active logger shared across the library.
	// Modules must use this logger rather than creating their own so that
	// all output flows through a single, user-configured sink.
	Logger() Logger

	// Keys returns the library's managed cryptographic material.
	// Sub-modules must call this to obtain signing keys and the refresh secret.
	Keys() Keys
}

// Module is the minimal contract every authcore authentication sub-module must
// implement. It acts as a marker interface today and will grow as shared
// lifecycle requirements (e.g. Close, HealthCheck) are identified.
//
// Available implementations:
//
//	auth/jwt      — JSON Web Token authentication (EdDSA / Ed25519)
//	auth/password — Argon2id password hashing
//	auth/email    — email validation and normalization
//
// Module constructors follow the convention:
//
//	func New(p authcore.Provider, cfg ...Config) (*T, error)
//
// where T is the concrete module type and cfg is the optional module-specific
// configuration. Omitting cfg applies safe, production-ready defaults.
type Module interface {
	// Name returns the unique, lowercase identifier of this module.
	// It must be stable across releases because callers may use it as a key.
	// Examples: "jwt", "apikey", "oauth"
	Name() string
}
