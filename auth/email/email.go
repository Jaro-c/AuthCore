// Package email provides email address validation and normalization for authcore.
//
// Validation follows RFC 5321 and RFC 5322 rules:
//   - Total length 1–254 characters
//   - Exactly one @ separating a non-empty local part and domain
//   - Local part ≤ 64 characters
//   - Domain contains at least one dot; no leading, trailing, or consecutive dots
//   - Each domain label is 1–63 characters
//
// Normalization lowercases and trims surrounding whitespace. Always normalize
// before storing and before querying — this ensures consistent lookup:
//
//	emailMod, _ := email.New(auth)
//
//	// Registration
//	normalized, err := emailMod.ValidateAndNormalize(req.Email)
//	if err != nil {
//	    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
//	    return
//	}
//	db.StoreUser(normalized, ...)
//
//	// Login lookup
//	normalized, err := emailMod.ValidateAndNormalize(req.Email)
//	if err != nil { ... }
//	user := db.FindByEmail(normalized)
//
// # Domain MX verification
//
// VerifyDomain performs an optional DNS MX lookup to confirm the domain can
// receive email. Results are cached per domain using the DNS TTL (capped at
// [DefaultCacheTTL]) to avoid repeated lookups for the same domain.
// This check is network I/O — always call it after ValidateAndNormalize and
// handle [ErrDomainUnresolvable] as a soft failure:
//
//	err = emailMod.VerifyDomain(ctx, normalized)
//	if errors.Is(err, email.ErrDomainNoMX) {
//	    c.JSON(400, map[string]string{"error": "email domain cannot receive messages"})
//	    return
//	}
//	if errors.Is(err, email.ErrDomainUnresolvable) {
//	    log.Warn("DNS check unavailable: %v", err) // do not block the user
//	}
package email

import (
	"context"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/Jaro-c/authcore"
)


// DefaultCacheTTL is the maximum duration a domain MX lookup result is cached.
// Tune this value if your workload has strict freshness requirements.
const DefaultCacheTTL = 5 * time.Minute

// maxCacheSize is the maximum number of domains held in the cache at once.
// When the limit is reached, expired entries are evicted before writing a new
// one. If the cache is still full after eviction, the new result is not cached
// (the next lookup will query DNS again). This bounds memory use even under
// an attack that submits millions of unique domains.
const maxCacheSize = 10_000

// cacheEntry holds the result of a single MX lookup.
type cacheEntry struct {
	hasMX      bool
	dnsFailure bool // true = DNS error, false = confirmed result
	expiresAt  time.Time
}

// Email is the email validation and normalization module.
// Create one instance at startup via New and reuse it — it is safe for
// concurrent use.
type Email struct {
	log      authcore.Logger
	resolver *net.Resolver
	cacheTTL time.Duration
	mu       sync.RWMutex
	cache    map[string]cacheEntry
}

// New creates an Email module using the provider's logger.
func New(p authcore.Provider) (*Email, error) {
	e := &Email{
		log:      p.Logger(),
		resolver: net.DefaultResolver,
		cacheTTL: DefaultCacheTTL,
		cache:    make(map[string]cacheEntry),
	}
	e.log.Info("email: module initialised")
	return e, nil
}

// Name implements authcore.Module.
func (e *Email) Name() string { return "email" }

// Normalize lowercases and trims surrounding whitespace from address.
// It does not validate — call Validate or ValidateAndNormalize for that.
func (e *Email) Normalize(address string) string {
	return strings.ToLower(strings.TrimSpace(address))
}

// Validate reports whether address is a well-formed email address.
// The address is expected to already be normalized (call Normalize first,
// or use ValidateAndNormalize to do both in one step).
//
// Returns nil on success, or [ErrInvalidEmail] wrapping the specific rule
// that failed. The wrapped reason is safe to show to the user.
func (e *Email) Validate(address string) error {
	return validate(address)
}

// ValidateAndNormalize normalizes address (lowercase + trim) and then
// validates it. Returns the normalized address on success.
//
// This is the recommended entry point for HTTP handlers:
//
//	normalized, err := emailMod.ValidateAndNormalize(req.Email)
//	if err != nil {
//	    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
//	    return
//	}
func (e *Email) ValidateAndNormalize(address string) (string, error) {
	normalized := e.Normalize(address)
	if err := validate(normalized); err != nil {
		return "", err
	}
	return normalized, nil
}

// validate checks address against RFC 5321 / RFC 5322 rules.
// It uses net/mail for syntax and then applies stricter structural checks.
func validate(address string) error {
	if len(address) == 0 {
		return &emailViolation{reason: fmt.Errorf("must not be empty")}
	}
	if len(address) > 254 {
		return &emailViolation{reason: fmt.Errorf("must be at most 254 characters")}
	}

	// net/mail.ParseAddress handles RFC 5322 syntax (quoted strings, comments, etc.).
	parsed, err := mail.ParseAddress(address)
	if err != nil {
		return &emailViolation{reason: fmt.Errorf("invalid format")}
	}

	// Reject display names like "Ana García <ana@example.com>".
	// EqualFold is intentional: net/mail may normalize domain case, so a
	// direct == would reject valid addresses when Validate is called without
	// prior normalization (e.g. "User@EXAMPLE.COM" vs "User@example.com").
	if !strings.EqualFold(address, parsed.Address) {
		return &emailViolation{reason: fmt.Errorf("invalid format")}
	}

	atIdx := strings.LastIndexByte(parsed.Address, '@')
	local := parsed.Address[:atIdx]
	domain := parsed.Address[atIdx+1:]

	if len(local) > 64 {
		return &emailViolation{reason: fmt.Errorf("local part must be at most 64 characters")}
	}

	// Domain: at least one dot, no leading/trailing/consecutive dots,
	// each label 1–63 characters.
	hasDot := false
	labelLen := 0
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if labelLen == 0 {
				return &emailViolation{reason: fmt.Errorf("domain must not start with or contain consecutive dots")}
			}
			hasDot = true
			labelLen = 0
		} else {
			labelLen++
			if labelLen > 63 {
				return &emailViolation{reason: fmt.Errorf("each domain label must be at most 63 characters")}
			}
		}
	}
	if !hasDot {
		return &emailViolation{reason: fmt.Errorf("domain must contain at least one dot")}
	}
	if labelLen == 0 {
		return &emailViolation{reason: fmt.Errorf("domain must not end with a dot")}
	}

	return nil
}

// VerifyDomain performs a DNS MX lookup to confirm that the email's domain
// can receive messages. It is an optional, network-bound complement to
// ValidateAndNormalize — call it only after format validation succeeds.
//
// Results are cached per domain for the duration of the DNS TTL, capped at
// [DefaultCacheTTL], to avoid repeated lookups for the same domain.
//
// On success it returns nil.
// On failure it returns one of:
//
//	[ErrDomainNoMX]         — domain exists but has no MX records (CLIENT-SAFE, return 400)
//	[ErrDomainUnresolvable] — DNS lookup failed; treat as a soft failure and do not block the user
//
// ctx controls the deadline of the DNS query. Use a short timeout (1–3 s) to
// avoid slowing down your registration endpoint:
//
//	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
//	defer cancel()
//	if err := emailMod.VerifyDomain(ctx, normalized); errors.Is(err, email.ErrDomainNoMX) {
//	    c.JSON(400, map[string]string{"error": "email domain cannot receive messages"})
//	    return
//	}
func (e *Email) VerifyDomain(ctx context.Context, address string) error {
	domain := domainOf(address)
	if domain == "" {
		return ErrDomainNoMX
	}

	// Fast path: check cache under read lock.
	e.mu.RLock()
	entry, ok := e.cache[domain]
	e.mu.RUnlock()
	if ok && time.Now().Before(entry.expiresAt) {
		if entry.dnsFailure {
			return ErrDomainUnresolvable
		}
		if !entry.hasMX {
			return ErrDomainNoMX
		}
		return nil
	}

	// Slow path: DNS lookup.
	mxs, err := e.resolver.LookupMX(ctx, domain)
	if err != nil {
		// Cache the DNS failure briefly (30 s) so a burst of requests for the
		// same unreachable domain does not hammer the resolver.
		// dnsFailure=true ensures subsequent cache hits return ErrDomainUnresolvable,
		// not ErrDomainNoMX, so callers never incorrectly block the user.
		e.store(domain, cacheEntry{dnsFailure: true, expiresAt: time.Now().Add(30 * time.Second)})
		return &domainUnresolvable{cause: err}
	}

	hasMX := len(mxs) > 0
	e.store(domain, cacheEntry{hasMX: hasMX, expiresAt: time.Now().Add(e.cacheTTL)})

	if !hasMX {
		return ErrDomainNoMX
	}
	return nil
}

// store writes entry into the cache under write lock.
// If the cache is at maxCacheSize, expired entries are evicted first.
// If still full after eviction, the entry is silently dropped — the next
// lookup will query DNS again, which is safe.
func (e *Email) store(domain string, entry cacheEntry) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.cache) >= maxCacheSize {
		now := time.Now()
		for k, v := range e.cache {
			if now.After(v.expiresAt) {
				delete(e.cache, k)
			}
		}
		if len(e.cache) >= maxCacheSize {
			return // still full — skip caching this entry
		}
	}
	e.cache[domain] = entry
}

// domainOf extracts the domain part of a normalized email address.
// Returns "" if address contains no '@'.
func domainOf(address string) string {
	i := strings.LastIndexByte(address, '@')
	if i < 0 {
		return ""
	}
	return address[i+1:]
}
