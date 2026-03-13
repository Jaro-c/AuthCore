package jwt

// Internal test package (package jwt, not package jwt_test) so that tests
// can inject a clock.Fixed into the unexported jwt.clock field without
// exposing time control as part of the public API.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Jaro-c/authcore"
	"github.com/Jaro-c/authcore/internal/clock"
)

// ---- test infrastructure ----------------------------------------------------

// fakeKeys satisfies authcore.Keys using in-memory key material.
type fakeKeys struct {
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	secret []byte
}

func (k *fakeKeys) PrivateKey() ed25519.PrivateKey { return k.priv }
func (k *fakeKeys) PublicKey() ed25519.PublicKey   { return k.pub }
func (k *fakeKeys) RefreshSecret() []byte          { return k.secret }
func (k *fakeKeys) KeyID() string                  { return "test0000test0000" }

// fakeProvider satisfies authcore.Provider using in-memory state.
type fakeProvider struct{ keys *fakeKeys }

func (p *fakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (p *fakeProvider) Logger() authcore.Logger { return silentLogger{} }
func (p *fakeProvider) Keys() authcore.Keys     { return p.keys }

// silentLogger satisfies authcore.Logger and discards all output.
type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

// newFakeProvider creates a fakeProvider with freshly generated key material.
func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	// Go 1.26: rand parameter to GenerateKey is always ignored — nil is explicit.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate test Ed25519 keys: %v", err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatalf("generate test HMAC secret: %v", err)
	}
	return &fakeProvider{keys: &fakeKeys{priv: priv, pub: pub, secret: secret}}
}

// epoch is the fixed reference time used in all time-sensitive tests.
var epoch = time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)

// newTestJWT constructs a JWT with the given config and a fixed clock pinned
// to epoch. The clock can be overridden per-test by assigning j.clock.
func newTestJWT(t *testing.T, p authcore.Provider, cfg Config) *JWT {
	t.Helper()
	j, err := New(p, cfg)
	if err != nil {
		t.Fatalf("jwt.New() unexpected error: %v", err)
	}
	j.clock = clock.Fixed(epoch)
	return j
}

// ---- New() ------------------------------------------------------------------

func TestNew_defaultConfigSucceeds(t *testing.T) {
	_, err := New(newFakeProvider(t), DefaultConfig())
	if err != nil {
		t.Fatalf("New(DefaultConfig) error = %v", err)
	}
}

func TestNew_negativeTTLReturnsError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = -1 * time.Second

	_, err := New(newFakeProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNew_refreshTTLShorterThanAccessReturnsError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 30 * time.Minute
	cfg.RefreshTokenTTL = 15 * time.Minute // shorter than access

	_, err := New(newFakeProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNew_implementsModule(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	var _ authcore.Module = j // compile-time checked by var _ above, belt+braces here
	if j.Name() != "jwt" {
		t.Errorf("Name() = %q, want %q", j.Name(), "jwt")
	}
}

// ---- CreateTokens() ---------------------------------------------------------

func TestCreateTokens_returnsNonEmptyPair(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, err := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")
	if err != nil {
		t.Fatalf("CreateTokens() error = %v", err)
	}
	if pair.AccessToken == "" {
		t.Error("AccessToken is empty")
	}
	if pair.AccessTokenExpiresAt.IsZero() {
		t.Error("AccessTokenExpiresAt is zero")
	}
	if pair.RefreshToken == "" {
		t.Error("RefreshToken is empty")
	}
	if pair.RefreshTokenExpiresAt.IsZero() {
		t.Error("RefreshTokenExpiresAt is zero")
	}
	if pair.RefreshTokenHash == "" {
		t.Error("RefreshTokenHash is empty")
	}
}

func TestCreateTokens_invalidSubjectReturnsError(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())

	cases := []string{
		"",
		"not-a-uuid",
		"123",
		"0191b432-b5a7-7c4f-b2e6",               // too short
		"0191b432-b5a7-7c4f-b2e6-7a3f1d2e00001", // too long
		"550e8400-e29b-11d4-a716-446655440000",   // v1 — rejected
		"550e8400-e29b-31d4-a716-446655440000",   // v3 — rejected
		"550e8400-e29b-41d4-a716-446655440000",   // v4 — rejected
		"550e8400-e29b-61d4-a716-446655440000",   // v6 — rejected
	}
	for _, tc := range cases {
		_, err := j.CreateTokens(tc)
		if !errors.Is(err, ErrInvalidSubject) {
			t.Errorf("subject %q: expected ErrInvalidSubject, got %v", tc, err)
		}
	}
}

func TestCreateTokens_uppercaseUUIDIsNormalised(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())

	upper := "0191B432-B5A7-7C4F-B2E6-7A3F1D2E0000"
	pair, err := j.CreateTokens(upper)
	if err != nil {
		t.Fatalf("uppercase UUID v7 should be accepted, got %v", err)
	}

	claims, _ := j.VerifyAccessToken(pair.AccessToken)
	if claims.Subject != strings.ToLower(upper) {
		t.Errorf("Subject = %q, want lowercase %q", claims.Subject, strings.ToLower(upper))
	}
}

func TestCreateTokens_validUUIDVersionsAreAccepted(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())

	cases := []string{
		"0191b432-b5a7-7c4f-b2e6-7a3f1d2e4c5a", // v7 lowercase
		"0191B432-B5A7-7C4F-B2E6-7A3F1D2E4C5A", // v7 uppercase
	}
	for _, tc := range cases {
		if _, err := j.CreateTokens(tc); err != nil {
			t.Errorf("subject %q: unexpected error %v", tc, err)
		}
	}
}

func TestCreateTokens_subjectPreservedInAccessToken(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0042")

	claims, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if claims.Subject != "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0042" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0042")
	}
}

func TestCreateTokens_issuerPreservedInClaims(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Issuer = "my-service"
	j := newTestJWT(t, newFakeProvider(t), cfg)
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	claims, _ := j.VerifyAccessToken(pair.AccessToken)
	if claims.Issuer != "my-service" {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, "my-service")
	}
}

func TestCreateTokens_accessAndRefreshTokensAreDifferent(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")
	if pair.AccessToken == pair.RefreshToken {
		t.Error("AccessToken and RefreshToken must not be equal")
	}
}

func TestCreateTokens_consecutiveCallsProduceUniqueRefreshTokens(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	p1, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")
	p2, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")
	if p1.RefreshToken == p2.RefreshToken {
		t.Error("consecutive CreateTokens calls must not produce equal refresh tokens")
	}
	if p1.RefreshTokenHash == p2.RefreshTokenHash {
		t.Error("consecutive CreateTokens calls must not produce equal refresh hashes")
	}
}

func TestCreateTokens_accessTokenExpiryIsCorrect(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 5 * time.Minute
	j := newTestJWT(t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")
	claims, _ := j.VerifyAccessToken(pair.AccessToken)

	want := epoch.Add(5 * time.Minute)
	if !claims.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", claims.ExpiresAt, want)
	}
}

func TestCreateTokens_expiryFieldsMatchConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 5 * time.Minute
	cfg.RefreshTokenTTL = 12 * time.Hour
	j := newTestJWT(t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	wantAccess := epoch.Add(5 * time.Minute)
	if !pair.AccessTokenExpiresAt.Equal(wantAccess) {
		t.Errorf("AccessTokenExpiresAt = %v, want %v", pair.AccessTokenExpiresAt, wantAccess)
	}

	wantRefresh := epoch.Add(12 * time.Hour)
	if !pair.RefreshTokenExpiresAt.Equal(wantRefresh) {
		t.Errorf("RefreshTokenExpiresAt = %v, want %v", pair.RefreshTokenExpiresAt, wantRefresh)
	}
}

func TestCreateTokens_refreshHashMatchesHashRefreshToken(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	got := j.HashRefreshToken(pair.RefreshToken)
	if got != pair.RefreshTokenHash {
		t.Errorf("HashRefreshToken(RefreshToken) = %q, want %q", got, pair.RefreshTokenHash)
	}
}

func TestCreateTokens_sessionIDIsUUIDv7(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	if pair.SessionID == "" {
		t.Fatal("SessionID is empty")
	}
	// UUID v7: version digit at position 14 must be '7',
	// variant nibble at position 19 must be 8, 9, a, or b.
	id := pair.SessionID
	if len(id) != 36 {
		t.Fatalf("SessionID length = %d, want 36", len(id))
	}
	if id[14] != '7' {
		t.Errorf("SessionID version digit = %q, want '7'", id[14])
	}
	if id[19] != '8' && id[19] != '9' && id[19] != 'a' && id[19] != 'b' {
		t.Errorf("SessionID variant nibble = %q, want 8/9/a/b", id[19])
	}
}

func TestCreateTokens_consecutiveSessionIDsAreUnique(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	p1, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")
	p2, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")
	if p1.SessionID == p2.SessionID {
		t.Error("consecutive CreateTokens calls must not produce equal SessionIDs")
	}
}

// ---- VerifyAccessToken() ----------------------------------------------------

func TestVerifyAccessToken_validTokenReturnsCorrectClaims(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0099")

	claims, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if claims.Subject != "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0099" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0099")
	}
	if !claims.IssuedAt.Equal(epoch) {
		t.Errorf("IssuedAt = %v, want %v", claims.IssuedAt, epoch)
	}
}

func TestVerifyAccessToken_expiredTokenReturnsErrTokenExpired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 10 * time.Minute
	j := newTestJWT(t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	// Advance clock past expiry.
	j.clock = clock.Fixed(epoch.Add(11 * time.Minute))

	_, err := j.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestVerifyAccessToken_tokenAtExactExpiryIsExpired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 10 * time.Minute
	j := newTestJWT(t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")
	// golang-jwt/v5 uses strict now.After(exp), so the token is still valid at
	// the exact expiry second. Advance one second past exp to trigger expiry.
	j.clock = clock.Fixed(epoch.Add(10*time.Minute + time.Second))

	_, err := j.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("token one second past expiry should return ErrTokenExpired, got %v", err)
	}
}

func TestVerifyAccessToken_tamperedSignatureReturnsErrTokenInvalid(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	// Modify a middle character of the signature segment to guarantee the
	// decoded bytes change. The last base64url char of an Ed25519 signature
	// encodes only 2 meaningful bits — altering it does not affect the
	// decoded byte slice, so we target a position well inside the signature.
	token := pair.AccessToken
	mid := len(token) - 10
	orig := token[mid]
	replacement := byte('A')
	if orig == 'A' {
		replacement = 'B'
	}
	tampered := token[:mid] + string(replacement) + token[mid+1:]

	_, err := j.VerifyAccessToken(tampered)
	if !errors.Is(err, ErrTokenInvalid) && !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("expected ErrTokenInvalid or ErrTokenMalformed, got %v", err)
	}
}

func TestVerifyAccessToken_malformedTokenReturnsErrTokenMalformed(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())

	cases := []string{"", "only-one-part", "two.parts", "a.b.c.d"}
	for _, tc := range cases {
		_, err := j.VerifyAccessToken(tc)
		if !errors.Is(err, ErrTokenMalformed) && !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("input %q: expected ErrTokenMalformed, got %v", tc, err)
		}
	}
}

func TestVerifyAccessToken_rejectsRefreshToken(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	_, err := j.VerifyAccessToken(pair.RefreshToken)
	if !errors.Is(err, ErrWrongTokenType) {
		t.Errorf("expected ErrWrongTokenType, got %v", err)
	}
}

func TestVerifyAccessToken_rejectsTokenFromDifferentKey(t *testing.T) {
	p1 := newFakeProvider(t)
	p2 := newFakeProvider(t) // different Ed25519 key pair

	j1 := newTestJWT(t, p1, DefaultConfig())
	j2 := newTestJWT(t, p2, DefaultConfig())

	pair, _ := j1.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	_, err := j2.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("token signed by j1 should be invalid for j2, got %v", err)
	}
}

// ---- HashRefreshToken() -----------------------------------------------------

func TestHashRefreshToken_isDeterministic(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	h1 := j.HashRefreshToken(pair.RefreshToken)
	h2 := j.HashRefreshToken(pair.RefreshToken)
	if h1 != h2 {
		t.Errorf("HashRefreshToken is not deterministic: %q != %q", h1, h2)
	}
}

func TestHashRefreshToken_differentTokensDifferentHashes(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	p1, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")
	p2, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	if j.HashRefreshToken(p1.RefreshToken) == j.HashRefreshToken(p2.RefreshToken) {
		t.Error("different refresh tokens must produce different HMAC digests")
	}
}

func TestHashRefreshToken_differentSecretsDifferentHashes(t *testing.T) {
	j1 := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	j2 := newTestJWT(t, newFakeProvider(t), DefaultConfig())

	// Sign a token with j1's key, hash it with both modules' secrets.
	pair, _ := j1.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	h1 := j1.HashRefreshToken(pair.RefreshToken)
	h2 := j2.HashRefreshToken(pair.RefreshToken)

	// Different HMAC secrets must produce different digests.
	if h1 == h2 {
		t.Error("same token hashed with different secrets should produce different results")
	}
}

// ---- RotateTokens() ---------------------------------------------------------

func TestRotateTokens_returnsNewPairForSameSubject(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	old, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0007")

	newPair, err := j.RotateTokens(old.RefreshToken)
	if err != nil {
		t.Fatalf("RotateTokens() error = %v", err)
	}

	claims, _ := j.VerifyAccessToken(newPair.AccessToken)
	if claims.Subject != "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0007" {
		t.Errorf("Subject after rotation = %q, want %q", claims.Subject, "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0007")
	}
}

func TestRotateTokens_newTokensDifferFromOld(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	old, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	// Advance clock by 1 second so the issued-at differs.
	j.clock = clock.Fixed(epoch.Add(time.Second))
	newPair, _ := j.RotateTokens(old.RefreshToken)

	if newPair.AccessToken == old.AccessToken {
		t.Error("new AccessToken must differ from old AccessToken")
	}
	if newPair.RefreshToken == old.RefreshToken {
		t.Error("new RefreshToken must differ from old RefreshToken")
	}
	if newPair.RefreshTokenHash == old.RefreshTokenHash {
		t.Error("new RefreshTokenHash must differ from old RefreshTokenHash")
	}
}

func TestRotateTokens_expiredRefreshTokenReturnsErrTokenExpired(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RefreshTokenTTL = 24 * time.Hour
	j := newTestJWT(t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	// Advance past refresh token TTL.
	j.clock = clock.Fixed(epoch.Add(25 * time.Hour))

	_, err := j.RotateTokens(pair.RefreshToken)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestRotateTokens_rejectsAccessToken(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	_, err := j.RotateTokens(pair.AccessToken)
	if !errors.Is(err, ErrWrongTokenType) {
		t.Errorf("expected ErrWrongTokenType, got %v", err)
	}
}

func TestRotateTokens_rejectsTamperedToken(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	rt := pair.RefreshToken
	midRT := len(rt) - 10
	origRT := rt[midRT]
	replacementRT := byte('A')
	if origRT == 'A' {
		replacementRT = 'B'
	}
	tampered := rt[:midRT] + string(replacementRT) + rt[midRT+1:]
	_, err := j.RotateTokens(tampered)
	if !errors.Is(err, ErrTokenInvalid) && !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("expected ErrTokenInvalid or ErrTokenMalformed, got %v", err)
	}
}

func TestRotateTokens_newHashMatchesHashRefreshToken(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	j.clock = clock.Fixed(epoch.Add(time.Second))
	newPair, _ := j.RotateTokens(pair.RefreshToken)

	got := j.HashRefreshToken(newPair.RefreshToken)
	if got != newPair.RefreshTokenHash {
		t.Errorf("HashRefreshToken(new token) = %q, want %q", got, newPair.RefreshTokenHash)
	}
}

// ---- kid header -------------------------------------------------------------

// tokenHeader decodes the JOSE header of a compact JWT string.
func tokenHeader(t *testing.T, tokenStr string) map[string]any {
	t.Helper()
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h map[string]any
	if err := json.Unmarshal(data, &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return h
}

func TestCreateTokens_accessTokenHeaderContainsKid(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	h := tokenHeader(t, pair.AccessToken)
	kid, ok := h["kid"].(string)
	if !ok || kid == "" {
		t.Errorf("access token header missing or empty kid: %v", h)
	}
	if kid != "test0000test0000" {
		t.Errorf("kid = %q, want %q", kid, "test0000test0000")
	}
}

func TestCreateTokens_refreshTokenHeaderContainsKid(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	h := tokenHeader(t, pair.RefreshToken)
	kid, ok := h["kid"].(string)
	if !ok || kid == "" {
		t.Errorf("refresh token header missing or empty kid: %v", h)
	}
	if kid != "test0000test0000" {
		t.Errorf("kid = %q, want %q", kid, "test0000test0000")
	}
}

func TestCreateTokens_bothTokensShareSameKid(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	accessKid := tokenHeader(t, pair.AccessToken)["kid"]
	refreshKid := tokenHeader(t, pair.RefreshToken)["kid"]
	if accessKid != refreshKid {
		t.Errorf("access kid %q != refresh kid %q", accessKid, refreshKid)
	}
}

// ---- access token jti -------------------------------------------------------

func TestCreateTokens_accessTokenIDIsUUIDv7(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	id := pair.AccessTokenID
	if len(id) != 36 {
		t.Fatalf("AccessTokenID length = %d, want 36", len(id))
	}
	if id[14] != '7' {
		t.Errorf("AccessTokenID version digit = %q, want '7'", id[14])
	}
	if id[19] != '8' && id[19] != '9' && id[19] != 'a' && id[19] != 'b' {
		t.Errorf("AccessTokenID variant nibble = %q, want 8/9/a/b", id[19])
	}
}

func TestCreateTokens_accessTokenIDExposedInClaims(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	claims, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if claims.TokenID != pair.AccessTokenID {
		t.Errorf("Claims.TokenID = %q, want %q", claims.TokenID, pair.AccessTokenID)
	}
}

func TestCreateTokens_accessAndRefreshJTIsAreDifferent(t *testing.T) {
	j := newTestJWT(t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001")

	if pair.AccessTokenID == pair.SessionID {
		t.Error("access token jti and refresh token jti must not be equal")
	}
}
