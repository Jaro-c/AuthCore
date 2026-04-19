package jwt

import (
	"fmt"
	"time"
)

// Config holds the JWT module configuration.
// All fields have safe defaults; use DefaultConfig() as the starting point.
type Config struct {
	// AccessTokenTTL is the lifetime of access tokens.
	// Defaults to 15 minutes.
	AccessTokenTTL time.Duration

	// RefreshTokenTTL is the lifetime of refresh tokens.
	// Must be strictly greater than AccessTokenTTL.
	// Defaults to 24 hours.
	RefreshTokenTTL time.Duration

	// Issuer is the value of the "iss" claim in every token issued by this
	// module, and the value VerifyAccessToken / RotateTokens require the
	// "iss" claim to match on verification. Tokens whose iss does not equal
	// this string are rejected with ErrTokenInvalid.
	//
	// Defaults to "github.com/Jaro-c/authcore".
	// Override this with your own service URL or identifier (e.g. "https://auth.example.com").
	Issuer string

	// Audience is the list of intended recipients embedded in the "aud" claim of every token.
	// Verifiers use this to confirm that a token was issued for their service.
	// Defaults to ["github.com/Jaro-c/authcore"].
	// Override this with your own service identifiers (e.g. ["https://api.example.com"]).
	Audience []string

	// ClockSkewLeeway is the tolerance applied when validating the "exp" and "iat" claims.
	// It compensates for small clock differences between distributed servers.
	// Defaults to 0 (no leeway). A value of 30 seconds is typical for production deployments.
	// Must not be negative.
	ClockSkewLeeway time.Duration
}

// DefaultConfig returns a Config with safe, production-ready defaults.
//
//	cfg := jwt.DefaultConfig()
//	cfg.AccessTokenTTL   = 5 * time.Minute          // tighten for high-security APIs
//	cfg.Issuer           = "https://auth.example.com"
//	cfg.Audience         = []string{"https://api.example.com"}
//	cfg.ClockSkewLeeway  = 30 * time.Second          // recommended for distributed deployments
//	jwtMod, err := jwt.New[MyClaims](auth, cfg)
func DefaultConfig() Config {
	return Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "github.com/Jaro-c/authcore",
		Audience:        []string{"github.com/Jaro-c/authcore"},
	}
}

// applyDefaults fills zero-value fields with values from DefaultConfig.
func applyDefaults(cfg Config) Config {
	def := DefaultConfig()
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = def.AccessTokenTTL
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = def.RefreshTokenTTL
	}
	if cfg.Issuer == "" {
		cfg.Issuer = def.Issuer
	}
	if len(cfg.Audience) == 0 {
		cfg.Audience = def.Audience
	}
	return cfg
}

// maxAccessTokenTTL and maxRefreshTokenTTL cap the configurable token
// lifetimes. They protect operators from accidentally issuing effectively
// permanent bearer tokens (for example by typing 10*time.Hour instead of
// 10*time.Minute). The ceilings match the longest values OWASP's JWT cheat
// sheet recommends for a typical web application.
const (
	maxAccessTokenTTL  = 24 * time.Hour
	maxRefreshTokenTTL = 365 * 24 * time.Hour
)

// validateConfig returns an error if cfg contains invalid or inconsistent values.
func validateConfig(cfg Config) error {
	if cfg.AccessTokenTTL <= 0 {
		return fmt.Errorf("access token TTL must be positive, got %s", cfg.AccessTokenTTL)
	}
	if cfg.AccessTokenTTL > maxAccessTokenTTL {
		return fmt.Errorf("access token TTL must be at most %s, got %s", maxAccessTokenTTL, cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL <= cfg.AccessTokenTTL {
		return fmt.Errorf(
			"refresh token TTL (%s) must be greater than access token TTL (%s)",
			cfg.RefreshTokenTTL, cfg.AccessTokenTTL,
		)
	}
	if cfg.RefreshTokenTTL > maxRefreshTokenTTL {
		return fmt.Errorf("refresh token TTL must be at most %s, got %s", maxRefreshTokenTTL, cfg.RefreshTokenTTL)
	}
	if len(cfg.Audience) == 0 {
		return fmt.Errorf("audience must contain at least one value")
	}
	if cfg.ClockSkewLeeway < 0 {
		return fmt.Errorf("clock skew leeway must not be negative, got %s", cfg.ClockSkewLeeway)
	}
	return nil
}
