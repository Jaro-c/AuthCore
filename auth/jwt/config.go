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

	// Issuer is the value of the "iss" claim in every token.
	// Defaults to "authcore".
	Issuer string
}

// DefaultConfig returns a Config with safe, production-ready defaults.
//
//	cfg := jwt.DefaultConfig()
//	cfg.AccessTokenTTL = 5 * time.Minute   // tighten for high-security APIs
//	jwtMod, err := jwt.New(auth, cfg)
func DefaultConfig() Config {
	return Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "authcore",
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
	return cfg
}

// validateConfig returns an error if cfg contains invalid or inconsistent values.
func validateConfig(cfg Config) error {
	if cfg.AccessTokenTTL <= 0 {
		return fmt.Errorf("access token TTL must be positive, got %s", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL <= cfg.AccessTokenTTL {
		return fmt.Errorf(
			"refresh token TTL (%s) must be greater than access token TTL (%s)",
			cfg.RefreshTokenTTL, cfg.AccessTokenTTL,
		)
	}
	return nil
}
