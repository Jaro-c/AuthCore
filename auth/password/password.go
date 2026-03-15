// Package password provides Argon2id password hashing for authcore.
//
// Argon2id is the memory-hard algorithm recommended by OWASP for password
// storage. It is resistant to GPU and ASIC brute-force attacks because it
// requires both significant CPU time and large amounts of RAM per attempt.
//
// # What is standardised
//
// The following parameters are fixed and cannot be changed — they represent
// security minimums that should not be weakened:
//
//   - Algorithm: Argon2id (RFC 9106)
//   - Salt length: 16 bytes (128 bits of cryptographically random material)
//   - Key length: 32 bytes (256-bit derived key)
//   - Output format: PHC string (portable, self-describing)
//
// # What is configurable
//
// The work parameters (Memory, Iterations, Parallelism) can be tuned to match
// your hardware. Higher values are always more secure; the defaults are sized
// for a server with 2+ vCPUs and 4+ GiB of RAM.
//
// # Typical server-side flow
//
//	// 1. Initialise once at startup.
//	auth, _   := authcore.New(authcore.DefaultConfig())
//	pwdMod, _ := password.New(auth, password.DefaultConfig())
//
//	// 2. Registration — hash the user's chosen password.
//	hash, err := pwdMod.Hash(userPassword)
//	if err != nil { ... }
//	db.StorePasswordHash(userID, hash)  // store the PHC string, never the plaintext
//
//	// 3. Login — verify the submitted password against the stored hash.
//	ok, err := pwdMod.Verify(submittedPassword, storedHash)
//	if err != nil { ... }               // ErrInvalidHash — hash is malformed
//	if !ok { return http.StatusUnauthorized }
//
//	// 4. Password change — verify current password first, then hash the new one.
//	ok, err := pwdMod.Verify(currentPassword, storedHash)
//	if !ok { return http.StatusUnauthorized }
//	newHash, err := pwdMod.Hash(newPassword)
//	db.UpdatePasswordHash(userID, newHash)
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Jaro-c/authcore"
	"golang.org/x/crypto/argon2"
)

const (
	saltLen = 16 // bytes — 128 bits of entropy per hash
	keyLen  = 32 // bytes — 256-bit Argon2id output
)

// Compile-time assertion: *Password must satisfy authcore.Module.
var _ authcore.Module = (*Password)(nil)

// Password is the authentication module for Argon2id password hashing.
//
// Construct one instance at application startup using New and share it
// across goroutines. Password is safe for concurrent use after construction.
type Password struct {
	cfg Config
	log authcore.Logger
}

// New creates and returns a Password module.
//
// p provides the logger sourced from the parent AuthCore instance.
// cfg controls the Argon2id work parameters; start from DefaultConfig.
func New(p authcore.Provider, cfg Config) (*Password, error) {
	cfg = applyDefaults(cfg)

	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	pw := &Password{cfg: cfg, log: p.Logger()}

	pw.log.Info("password: module initialised (memory=%dKiB, iterations=%d, parallelism=%d)",
		cfg.Memory, cfg.Iterations, cfg.Parallelism)

	return pw, nil
}

// Name returns the module's unique identifier. It implements authcore.Module.
func (p *Password) Name() string { return "password" }

// Hash derives an Argon2id hash from plaintext and returns it encoded in PHC
// string format. A fresh cryptographically random salt is generated per call,
// so two calls with the same input will produce different (but equivalent) hashes.
//
// Store the returned string in your database. Never store the plaintext password.
//
//	hash, err := pwdMod.Hash(userPassword)
//	if err != nil { ... }
//	db.StorePasswordHash(userID, hash)
func (p *Password) Hash(plaintext string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(plaintext), salt, p.cfg.Iterations, p.cfg.Memory, p.cfg.Parallelism, keyLen)

	// PHC string format: $argon2id$v=19$m=<mem>,t=<iter>,p=<par>$<salt>$<key>
	// Salt and key are base64 encoded without padding (RFC 4648 §5).
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.cfg.Memory,
		p.cfg.Iterations,
		p.cfg.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)

	return encoded, nil
}

// Verify reports whether plaintext matches the Argon2id hash in phcHash.
//
// The Argon2id parameters (Memory, Iterations, Parallelism) are read from
// phcHash itself, so stored hashes remain valid even if the module's Config
// is updated after they were created.
//
// The comparison is performed in constant time to prevent timing attacks.
//
//	ok, err := pwdMod.Verify(submittedPassword, storedHash)
//	if errors.Is(err, password.ErrInvalidHash) { ... } // hash is malformed
//	if !ok { return http.StatusUnauthorized }
func (p *Password) Verify(plaintext, phcHash string) (bool, error) {
	params, salt, storedKey, err := parsePHC(phcHash)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrInvalidHash, err)
	}

	key := argon2.IDKey([]byte(plaintext), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(storedKey)))

	return subtle.ConstantTimeCompare(key, storedKey) == 1, nil
}

// parsePHC decodes a PHC string produced by Hash and returns the embedded
// Argon2id parameters, the decoded salt, and the decoded derived key.
func parsePHC(phcHash string) (Config, []byte, []byte, error) {
	// Expected: $argon2id$v=19$m=<mem>,t=<iter>,p=<par>$<salt>$<key>
	// strings.Split on "$" produces: ["", "argon2id", "v=19", "m=...", "<salt>", "<key>"]
	parts := strings.Split(phcHash, "$")
	if len(parts) != 6 {
		return Config{}, nil, nil, fmt.Errorf("expected 6 dollar-separated segments, got %d", len(parts))
	}
	if parts[1] != "argon2id" {
		return Config{}, nil, nil, fmt.Errorf("unsupported algorithm %q, want argon2id", parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Config{}, nil, nil, fmt.Errorf("parse version: %w", err)
	}
	if version != argon2.Version {
		return Config{}, nil, nil, fmt.Errorf("unsupported Argon2 version %d, want %d", version, argon2.Version)
	}

	var cfg Config
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &cfg.Memory, &cfg.Iterations, &cfg.Parallelism); err != nil {
		return Config{}, nil, nil, fmt.Errorf("parse parameters: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Config{}, nil, nil, fmt.Errorf("decode salt: %w", err)
	}

	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Config{}, nil, nil, fmt.Errorf("decode key: %w", err)
	}

	return cfg, salt, key, nil
}
