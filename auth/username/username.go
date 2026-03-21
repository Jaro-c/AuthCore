// Package username provides username validation and normalization for authcore.
//
// Validation rules (applied after normalization):
//   - Length between [minLength] and [maxLength] (fixed: 3–32 characters)
//   - Only lowercase letters, digits, underscores, and hyphens: [a-z0-9_-]
//   - Must start and end with a letter or digit (not _ or -)
//   - No consecutive special characters (__, --, _-, -_)
//   - Not in the built-in reserved names list, nor in [Config.ExtraReserved]
//
// The single entry point is [Username.ValidateAndNormalize] — it normalizes
// (lowercase + trim) and validates in one step, returning the canonical form.
// Always store and query usernames using this canonical form:
//
//	userMod, _ := username.New(auth)
//
//	// Registration
//	normalized, err := userMod.ValidateAndNormalize(req.Username)
//	if err != nil {
//	    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
//	    return
//	}
//	db.StoreUser(normalized, ...)
//
//	// Login lookup — same call, same canonical form, consistent results
//	normalized, err = userMod.ValidateAndNormalize(req.Username)
//	if err != nil { ... }
//	user := db.FindByUsername(normalized)
package username

import (
	"fmt"
	"strings"

	"github.com/Jaro-c/authcore"
)

// Compile-time assertion: *Username must satisfy authcore.Module.
var _ authcore.Module = (*Username)(nil)

// Username is the username validation and normalization module.
//
// Construct one instance at application startup using New and share it
// across goroutines. Username is safe for concurrent use after construction.
type Username struct {
	cfg      Config
	log      authcore.Logger
	reserved map[string]struct{} // O(1) lookup set built at New() time
}

// New creates a Username module using the provider's logger.
//
// cfg is optional — omit it for zero-config usage (built-in reserved names only).
// Pass a Config only to add application-specific reserved names:
//
//	// zero-config — fixed rules, no boilerplate
//	userMod, err := username.New(auth)
//
//	// extend the reserved names list with your product's own names
//	userMod, err := username.New(auth, username.Config{
//	    ExtraReserved: []string{"yourappname", "yourcompany"},
//	})
func New(p authcore.Provider, cfg ...Config) (*Username, error) {
	// Accept an optional Config via variadic to allow zero-config usage:
	//   username.New(auth)             — built-in reserved names only, no boilerplate
	//   username.New(auth, customCfg)  — adds application-specific reserved names
	var resolved Config
	if len(cfg) > 0 {
		resolved = cfg[0]
	}

	// Build the reserved names lookup set once at startup so every
	// ValidateAndNormalize call gets O(1) map lookup instead of O(n) slice scan.
	reserved := make(map[string]struct{}, len(defaultReservedNames)+len(resolved.ExtraReserved))
	for _, name := range defaultReservedNames {
		reserved[name] = struct{}{}
	}
	for _, name := range resolved.ExtraReserved {
		// Normalize extra reserved names so the comparison is case-insensitive
		// and whitespace-tolerant regardless of how the caller provided them.
		reserved[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}

	u := &Username{cfg: resolved, log: p.Logger(), reserved: reserved}
	u.log.Info("username: module initialised (reserved=%d)", len(reserved))
	return u, nil
}

// Name returns the module's unique identifier. It implements authcore.Module.
func (u *Username) Name() string { return "username" }

// ValidateAndNormalize is the single entry point for username validation.
// It lowercases, trims surrounding whitespace, and validates the username
// against all rules in one atomic step.
//
// Always use this function — never normalize and validate separately.
// The returned string is the canonical form that must be stored and queried:
//
//	normalized, err := userMod.ValidateAndNormalize(req.Username)
//	if err != nil {
//	    // errors.Unwrap(err).Error() contains the specific rule that failed.
//	    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
//	    return
//	}
//	db.StoreUser(normalized, ...) // always lowercase, trimmed, validated
func (u *Username) ValidateAndNormalize(raw string) (string, error) {
	// Normalize first so validation sees the canonical form.
	// Storing the normalized form ensures consistent lookups:
	// "Alice123" and "alice123" resolve to the same record.
	normalized := normalize(raw)
	if err := u.validate(normalized); err != nil {
		return "", err
	}
	return normalized, nil
}

// normalize lowercases and trims surrounding whitespace. Internal only —
// callers outside this package must use ValidateAndNormalize.
func normalize(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// validate checks username against all rules.
// It assumes the input has already been normalized (lowercase + trimmed).
func (u *Username) validate(username string) error {
	n := len(username)

	if n == 0 {
		return &usernameViolation{reason: fmt.Errorf("must not be empty")}
	}
	if n < minLength {
		return &usernameViolation{reason: fmt.Errorf("must be at least %d characters", minLength)}
	}
	if n > maxLength {
		return &usernameViolation{reason: fmt.Errorf("must be at most %d characters", maxLength)}
	}

	// First character must be a letter or digit — not _ or -.
	// This prevents usernames like "-user" or "_user" which look ambiguous
	// in URLs and @ mentions.
	if !isAlphanumeric(username[0]) {
		return &usernameViolation{reason: fmt.Errorf("must start with a letter or digit")}
	}

	// Last character must be a letter or digit for the same reason.
	if !isAlphanumeric(username[n-1]) {
		return &usernameViolation{reason: fmt.Errorf("must end with a letter or digit")}
	}

	// Walk the username once to check:
	//   1. Only allowed characters: [a-z0-9_-]
	//   2. No consecutive special characters: __, --, _-, -_
	//      Consecutive specials look odd and are often a sign of a typo.
	prevSpecial := false
	for i := 0; i < n; i++ {
		c := username[i]
		if !isAllowed(c) {
			return &usernameViolation{reason: fmt.Errorf("may only contain letters, digits, underscores, and hyphens")}
		}
		isSpecial := c == '_' || c == '-'
		if isSpecial && prevSpecial {
			return &usernameViolation{reason: fmt.Errorf("must not contain consecutive underscores or hyphens")}
		}
		prevSpecial = isSpecial
	}

	// Reserved name check — O(1) map lookup.
	// Done last so length/character errors surface first (more actionable for users).
	if _, ok := u.reserved[username]; ok {
		return &usernameViolation{reason: fmt.Errorf("%q is a reserved name", username)}
	}

	return nil
}

// isAlphanumeric reports whether b is [a-z0-9].
// Only called on already-normalized (lowercase) input.
func isAlphanumeric(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// isAllowed reports whether b is in the permitted set [a-z0-9_-].
// Only called on already-normalized (lowercase) input.
func isAllowed(b byte) bool {
	return isAlphanumeric(b) || b == '_' || b == '-'
}
