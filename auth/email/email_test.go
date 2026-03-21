package email

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/Jaro-c/authcore"
)

// ---- test helpers -----------------------------------------------------------

type fakeProvider struct{}

func (fakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (fakeProvider) Logger() authcore.Logger  { return silentLogger{} }
func (fakeProvider) Keys() authcore.Keys      { return nil }

type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

func newMod(t *testing.T) *Email {
	t.Helper()
	m, err := New(fakeProvider{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// ---- New() ------------------------------------------------------------------

func TestNew_succeeds(t *testing.T) {
	if _, err := New(fakeProvider{}); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestName(t *testing.T) {
	if got := newMod(t).Name(); got != "email" {
		t.Errorf("Name() = %q, want %q", got, "email")
	}
}

// ---- Normalize() ------------------------------------------------------------

func TestNormalize_lowercases(t *testing.T) {
	m := newMod(t)
	if got := m.Normalize("USER@EXAMPLE.COM"); got != "user@example.com" {
		t.Errorf("got %q", got)
	}
}

func TestNormalize_trimsSpaces(t *testing.T) {
	m := newMod(t)
	if got := m.Normalize("  user@example.com  "); got != "user@example.com" {
		t.Errorf("got %q", got)
	}
}

func TestNormalize_mixedCaseAndSpaces(t *testing.T) {
	m := newMod(t)
	if got := m.Normalize("  Ana@Example.COM  "); got != "ana@example.com" {
		t.Errorf("got %q", got)
	}
}

// ---- Validate() — valid addresses -------------------------------------------

func TestValidate_simpleValid(t *testing.T) {
	valid := []string{
		"user@example.com",
		"user.name@example.com",
		"user+tag@example.co.uk",
		"a@b.io",
		"user@sub.domain.example.com",
	}
	m := newMod(t)
	for _, addr := range valid {
		if err := m.Validate(addr); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", addr, err)
		}
	}
}

// ---- Validate() — invalid addresses -----------------------------------------

func TestValidate_empty(t *testing.T) {
	if err := newMod(t).Validate(""); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_tooLong(t *testing.T) {
	// 255-character address
	local := "a"
	for len(local+"@b.com") <= 254 {
		local += "a"
	}
	if err := newMod(t).Validate(local + "@b.com"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail for too-long address")
	}
}

func TestValidate_noAt(t *testing.T) {
	if err := newMod(t).Validate("userexample.com"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_localPartTooLong(t *testing.T) {
	local := ""
	for i := 0; i < 65; i++ {
		local += "a"
	}
	if err := newMod(t).Validate(local + "@example.com"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail for local part > 64 chars")
	}
}

func TestValidate_domainNoDot(t *testing.T) {
	if err := newMod(t).Validate("user@localhost"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_domainLeadingDot(t *testing.T) {
	if err := newMod(t).Validate("user@.example.com"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_domainTrailingDot(t *testing.T) {
	if err := newMod(t).Validate("user@example.com."); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_domainConsecutiveDots(t *testing.T) {
	if err := newMod(t).Validate("user@example..com"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidate_withDisplayName(t *testing.T) {
	if err := newMod(t).Validate("Ana <ana@example.com>"); !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail for display name format")
	}
}

// ---- Validate() — ErrInvalidEmail wraps a reason ---------------------------

func TestValidate_wrapsReason(t *testing.T) {
	err := newMod(t).Validate("")
	if !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("expected ErrInvalidEmail, got %v", err)
	}
	reason := errors.Unwrap(err)
	if reason == nil {
		t.Fatal("expected wrapped reason, got nil")
	}
	if reason.Error() == "" {
		t.Error("wrapped reason must not be empty")
	}
}

// ---- ValidateAndNormalize() -------------------------------------------------

func TestValidateAndNormalize_normalizes(t *testing.T) {
	m := newMod(t)
	got, err := m.ValidateAndNormalize("  USER@EXAMPLE.COM  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "user@example.com" {
		t.Errorf("got %q, want %q", got, "user@example.com")
	}
}

func TestValidateAndNormalize_invalidReturnsError(t *testing.T) {
	_, err := newMod(t).ValidateAndNormalize("not-an-email")
	if !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

func TestValidateAndNormalize_emptyReturnsError(t *testing.T) {
	_, err := newMod(t).ValidateAndNormalize("")
	if !errors.Is(err, ErrInvalidEmail) {
		t.Errorf("expected ErrInvalidEmail, got %v", err)
	}
}

// ---- VerifyDomain() tests ---------------------------------------------------

// primeCache directly writes a cache entry, bypassing DNS, so we can test
// cache hit behaviour without network access.
func primeCache(m *Email, domain string, hasMX bool, ttl time.Duration) {
	m.mu.Lock()
	m.cache[domain] = cacheEntry{hasMX: hasMX, expiresAt: time.Now().Add(ttl)}
	m.mu.Unlock()
}

func TestVerifyDomain_cachedPositiveReturnsNil(t *testing.T) {
	m := newMod(t)
	primeCache(m, "example.com", true, time.Minute)

	if err := m.VerifyDomain(context.Background(), "user@example.com"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestVerifyDomain_cachedNegativeReturnsErrDomainNoMX(t *testing.T) {
	m := newMod(t)
	primeCache(m, "nodomain.example", false, time.Minute)

	err := m.VerifyDomain(context.Background(), "user@nodomain.example")
	if !errors.Is(err, ErrDomainNoMX) {
		t.Errorf("expected ErrDomainNoMX, got %v", err)
	}
}

func TestVerifyDomain_expiredCacheHitsDNS(t *testing.T) {
	m := newMod(t)
	// Write an expired positive entry — it must NOT be used.
	m.mu.Lock()
	m.cache["example.com"] = cacheEntry{hasMX: true, expiresAt: time.Now().Add(-time.Second)}
	m.mu.Unlock()

	// DNS will fail (no real network in unit tests using a broken resolver).
	m.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("no network")
		},
	}
	err := m.VerifyDomain(context.Background(), "user@example.com")
	if !errors.Is(err, ErrDomainUnresolvable) {
		t.Errorf("expected ErrDomainUnresolvable after cache miss + DNS failure, got %v", err)
	}
}

func TestVerifyDomain_dnsFailureReturnsErrDomainUnresolvable(t *testing.T) {
	m := newMod(t)
	m.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("no network")
		},
	}
	err := m.VerifyDomain(context.Background(), "user@unreachable.example")
	if !errors.Is(err, ErrDomainUnresolvable) {
		t.Errorf("expected ErrDomainUnresolvable, got %v", err)
	}
}

func TestVerifyDomain_dnsFailureIsWrapped(t *testing.T) {
	m := newMod(t)
	m.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("no network")
		},
	}
	err := m.VerifyDomain(context.Background(), "user@unreachable.example")
	if errors.Unwrap(err) == nil {
		t.Error("ErrDomainUnresolvable must wrap the underlying DNS error")
	}
}

func TestVerifyDomain_noAtSignReturnsErrDomainNoMX(t *testing.T) {
	m := newMod(t)
	err := m.VerifyDomain(context.Background(), "notanemail")
	if !errors.Is(err, ErrDomainNoMX) {
		t.Errorf("expected ErrDomainNoMX for address with no '@', got %v", err)
	}
}

func TestVerifyDomain_cachedDnsFailureReturnsErrDomainUnresolvable(t *testing.T) {
	// Regression: a DNS failure cached as hasMX=false must NOT return
	// ErrDomainNoMX on subsequent cache hits — that would incorrectly block
	// the user. It must return ErrDomainUnresolvable (soft failure).
	m := newMod(t)
	m.mu.Lock()
	m.cache["unreachable.example"] = cacheEntry{
		dnsFailure: true,
		expiresAt:  time.Now().Add(time.Minute),
	}
	m.mu.Unlock()

	err := m.VerifyDomain(context.Background(), "user@unreachable.example")
	if !errors.Is(err, ErrDomainUnresolvable) {
		t.Errorf("cached DNS failure must return ErrDomainUnresolvable, got %v", err)
	}
	if errors.Is(err, ErrDomainNoMX) {
		t.Error("cached DNS failure must NOT return ErrDomainNoMX")
	}
}

func TestVerifyDomain_cacheEvictsExpiredWhenFull(t *testing.T) {
	m := newMod(t)

	// Fill the cache to maxCacheSize with already-expired entries.
	m.mu.Lock()
	for i := range maxCacheSize {
		m.cache[fmt.Sprintf("expired%d.example", i)] = cacheEntry{
			hasMX:     true,
			expiresAt: time.Now().Add(-time.Second), // already expired
		}
	}
	m.mu.Unlock()

	// Storing a new entry must evict the expired ones and succeed.
	m.store("new.example", cacheEntry{hasMX: true, expiresAt: time.Now().Add(time.Minute)})

	m.mu.RLock()
	_, ok := m.cache["new.example"]
	size := len(m.cache)
	m.mu.RUnlock()

	if !ok {
		t.Error("new entry must be stored after expired entries are evicted")
	}
	if size > maxCacheSize {
		t.Errorf("cache size %d exceeds maxCacheSize %d", size, maxCacheSize)
	}
}

func TestVerifyDomain_dnsFailureCachesNegativeBriefly(t *testing.T) {
	m := newMod(t)
	m.resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("no network")
		},
	}
	_ = m.VerifyDomain(context.Background(), "user@unreachable.example")

	// Second call must hit the cache (no second DNS attempt).
	// We verify by reading the cache directly.
	m.mu.RLock()
	entry, ok := m.cache["unreachable.example"]
	m.mu.RUnlock()
	if !ok {
		t.Fatal("expected a cache entry after DNS failure")
	}
	if entry.hasMX {
		t.Error("failed DNS lookup must cache hasMX=false")
	}
	if time.Until(entry.expiresAt) > 31*time.Second {
		t.Errorf("negative DNS failure TTL should be ≤30 s, got %v", time.Until(entry.expiresAt))
	}
}
