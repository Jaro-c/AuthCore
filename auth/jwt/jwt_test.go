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

// newTestJWT constructs a JWT[T] with the given config and a fixed clock pinned
// to epoch. The clock can be overridden per-test by assigning j.clock.
func newTestJWT[T any](t *testing.T, p authcore.Provider, cfg Config) *JWT[T] {
	t.Helper()
	j, err := New[T](p, cfg)
	if err != nil {
		t.Fatalf("jwt.New() unexpected error: %v", err)
	}
	j.clock = clock.Fixed(epoch)
	return j
}

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

// testSubject is a valid UUID v7 used across most tests.
const testSubject = "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0001"

// ---- New() ------------------------------------------------------------------

func TestNew_defaultConfigSucceeds(t *testing.T) {
	_, err := New[struct{}](newFakeProvider(t), DefaultConfig())
	if err != nil {
		t.Fatalf("New(DefaultConfig) error = %v", err)
	}
}

func TestNew_negativeTTLReturnsError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = -1 * time.Second

	_, err := New[struct{}](newFakeProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNew_refreshTTLShorterThanAccessReturnsError(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 30 * time.Minute
	cfg.RefreshTokenTTL = 15 * time.Minute // shorter than access

	_, err := New[struct{}](newFakeProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNew_implementsModule(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	var _ authcore.Module = j // compile-time checked by var _ above, belt+braces here
	if j.Name() != "jwt" {
		t.Errorf("Name() = %q, want %q", j.Name(), "jwt")
	}
}

// ---- CreateTokens() ---------------------------------------------------------

func TestCreateTokens_returnsNonEmptyPair(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, err := j.CreateTokens(testSubject, struct{}{})
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
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())

	cases := []string{
		"",
		"not-a-uuid",
		"123",
		"0191b432-b5a7-7c4f-b2e6",               // too short
		"0191b432-b5a7-7c4f-b2e6-7a3f1d2e00001", // too long
		"550e8400-e29b-11d4-a716-446655440000",  // v1 — rejected
		"550e8400-e29b-31d4-a716-446655440000",  // v3 — rejected
		"550e8400-e29b-41d4-a716-446655440000",  // v4 — rejected
		"550e8400-e29b-61d4-a716-446655440000",  // v6 — rejected
	}
	for _, tc := range cases {
		_, err := j.CreateTokens(tc, struct{}{})
		if !errors.Is(err, ErrInvalidSubject) {
			t.Errorf("subject %q: expected ErrInvalidSubject, got %v", tc, err)
		}
	}
}

func TestCreateTokens_uppercaseUUIDIsNormalised(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())

	upper := "0191B432-B5A7-7C4F-B2E6-7A3F1D2E0000"
	pair, err := j.CreateTokens(upper, struct{}{})
	if err != nil {
		t.Fatalf("uppercase UUID v7 should be accepted, got %v", err)
	}

	claims, _ := j.VerifyAccessToken(pair.AccessToken)
	if claims.Subject != strings.ToLower(upper) {
		t.Errorf("Subject = %q, want lowercase %q", claims.Subject, strings.ToLower(upper))
	}
}

func TestCreateTokens_validUUIDVersionsAreAccepted(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())

	cases := []string{
		"0191b432-b5a7-7c4f-b2e6-7a3f1d2e4c5a", // v7 lowercase
		"0191B432-B5A7-7C4F-B2E6-7A3F1D2E4C5A", // v7 uppercase
	}
	for _, tc := range cases {
		if _, err := j.CreateTokens(tc, struct{}{}); err != nil {
			t.Errorf("subject %q: unexpected error %v", tc, err)
		}
	}
}

func TestCreateTokens_subjectPreservedInAccessToken(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0042", struct{}{})

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
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	claims, _ := j.VerifyAccessToken(pair.AccessToken)
	if claims.Issuer != "my-service" {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, "my-service")
	}
}

func TestCreateTokens_accessAndRefreshTokensAreDifferent(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})
	if pair.AccessToken == pair.RefreshToken {
		t.Error("AccessToken and RefreshToken must not be equal")
	}
}

func TestCreateTokens_consecutiveCallsProduceUniqueRefreshTokens(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	p1, _ := j.CreateTokens(testSubject, struct{}{})
	p2, _ := j.CreateTokens(testSubject, struct{}{})
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
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens(testSubject, struct{}{})
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
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens(testSubject, struct{}{})

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
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	got := j.HashRefreshToken(pair.RefreshToken)
	if got != pair.RefreshTokenHash {
		t.Errorf("HashRefreshToken(RefreshToken) = %q, want %q", got, pair.RefreshTokenHash)
	}
}

func TestCreateTokens_sessionIDIsUUIDv7(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	if pair.SessionID == "" {
		t.Fatal("SessionID is empty")
	}
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
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	p1, _ := j.CreateTokens(testSubject, struct{}{})
	p2, _ := j.CreateTokens(testSubject, struct{}{})
	if p1.SessionID == p2.SessionID {
		t.Error("consecutive CreateTokens calls must not produce equal SessionIDs")
	}
}

// ---- audience ---------------------------------------------------------------

func TestCreateTokens_audienceEmbeddedInAccessToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Audience = []string{"https://api.example.com"}
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	claims, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "https://api.example.com" {
		t.Errorf("Audience = %v, want [https://api.example.com]", claims.Audience)
	}
}

func TestCreateTokens_wrongAudienceRejectsToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Audience = []string{"https://api.example.com"}
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	// Verify with a different audience config — must fail.
	cfg2 := DefaultConfig()
	cfg2.Audience = []string{"https://other.example.com"}
	j2 := newTestJWT[struct{}](t, newFakeProvider(t), cfg2)
	j2.priv = j.priv
	j2.pub = j.pub

	_, err := j2.VerifyAccessToken(pair.AccessToken)
	if err == nil {
		t.Error("expected error when audience does not match, got nil")
	}
}

func TestVerifyAccessToken_wrongIssuerRejectsToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Issuer = "https://auth.service-a.example.com"
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	// Another service that happens to share the signing key (e.g. accidental
	// key reuse across microservices) must not accept a token issued by the
	// first service. The iss claim must be checked on verification.
	cfg2 := DefaultConfig()
	cfg2.Issuer = "https://auth.service-b.example.com"
	j2 := newTestJWT[struct{}](t, newFakeProvider(t), cfg2)
	j2.priv = j.priv
	j2.pub = j.pub

	_, err := j2.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid when issuer does not match, got %v", err)
	}
}

func TestRotateTokens_wrongIssuerRejectsRefreshToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Issuer = "https://auth.service-a.example.com"
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	cfg2 := DefaultConfig()
	cfg2.Issuer = "https://auth.service-b.example.com"
	j2 := newTestJWT[struct{}](t, newFakeProvider(t), cfg2)
	j2.priv = j.priv
	j2.pub = j.pub

	_, err := j2.RotateTokens(pair.RefreshToken, struct{}{})
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("expected ErrTokenInvalid when issuer does not match, got %v", err)
	}
}

func TestRotateTokens_audienceEmbeddedInRefreshToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Audience = []string{"https://api.example.com"}
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	// Rotation must succeed — refresh token carries the same audience.
	j.clock = clock.Fixed(epoch.Add(time.Second))
	_, err := j.RotateTokens(pair.RefreshToken, struct{}{})
	if err != nil {
		t.Fatalf("RotateTokens() error = %v", err)
	}
}

// ---- custom claims ----------------------------------------------------------

type testUserClaims struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

func TestCreateTokens_customClaimsRoundTrip(t *testing.T) {
	j := newTestJWT[testUserClaims](t, newFakeProvider(t), DefaultConfig())
	extra := testUserClaims{Name: "Juan", Role: "admin"}

	pair, err := j.CreateTokens(testSubject, extra)
	if err != nil {
		t.Fatalf("CreateTokens() error = %v", err)
	}

	claims, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if claims.Extra.Name != "Juan" {
		t.Errorf("Extra.Name = %q, want %q", claims.Extra.Name, "Juan")
	}
	if claims.Extra.Role != "admin" {
		t.Errorf("Extra.Role = %q, want %q", claims.Extra.Role, "admin")
	}
}

func TestCreateTokens_refreshTokenHasNoExtraClaims(t *testing.T) {
	j := newTestJWT[testUserClaims](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, testUserClaims{Name: "Juan", Role: "admin"})

	// Decode the refresh token payload and verify "extra" is absent.
	parts := strings.SplitN(pair.RefreshToken, ".", 3)
	data, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal refresh payload: %v", err)
	}
	if _, ok := payload["extra"]; ok {
		t.Error("refresh token payload must not contain 'extra' field")
	}
}

func TestCreateTokens_refreshTokenHasIat(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	parts := strings.SplitN(pair.RefreshToken, ".", 3)
	data, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal refresh payload: %v", err)
	}
	if _, ok := payload["iat"]; !ok {
		t.Error("refresh token payload must contain 'iat' field")
	}
}

// ---- kid header -------------------------------------------------------------

func TestCreateTokens_accessTokenHeaderContainsKid(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

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
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

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
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	accessKid := tokenHeader(t, pair.AccessToken)["kid"]
	refreshKid := tokenHeader(t, pair.RefreshToken)["kid"]
	if accessKid != refreshKid {
		t.Errorf("access kid %q != refresh kid %q", accessKid, refreshKid)
	}
}

// ---- access token jti -------------------------------------------------------

func TestCreateTokens_sessionIDIsUUIDv7Format(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

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

func TestCreateTokens_accessAndRefreshShareSameJTI(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	claims, err := j.VerifyAccessToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if claims.TokenID != pair.SessionID {
		t.Errorf("access token jti %q must equal SessionID %q", claims.TokenID, pair.SessionID)
	}
}

// ---- VerifyAccessToken() ----------------------------------------------------

func TestVerifyAccessToken_validTokenReturnsCorrectClaims(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0099", struct{}{})

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
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens(testSubject, struct{}{})

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
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens(testSubject, struct{}{})
	// golang-jwt/v5 uses strict now.After(exp), so the token is still valid at
	// the exact expiry second. Advance one second past exp to trigger expiry.
	j.clock = clock.Fixed(epoch.Add(10*time.Minute + time.Second))

	_, err := j.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("token one second past expiry should return ErrTokenExpired, got %v", err)
	}
}

func TestVerifyAccessToken_tamperedSignatureReturnsErrTokenInvalid(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

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
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())

	cases := []string{"", "only-one-part", "two.parts", "a.b.c.d"}
	for _, tc := range cases {
		_, err := j.VerifyAccessToken(tc)
		if !errors.Is(err, ErrTokenMalformed) && !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("input %q: expected ErrTokenMalformed, got %v", tc, err)
		}
	}
}

func TestVerifyAccessToken_rejectsRefreshToken(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	_, err := j.VerifyAccessToken(pair.RefreshToken)
	if !errors.Is(err, ErrWrongTokenType) {
		t.Errorf("expected ErrWrongTokenType, got %v", err)
	}
}

func TestVerifyAccessToken_rejectsTokenFromDifferentKey(t *testing.T) {
	p1 := newFakeProvider(t)
	p2 := newFakeProvider(t) // different Ed25519 key pair

	j1 := newTestJWT[struct{}](t, p1, DefaultConfig())
	j2 := newTestJWT[struct{}](t, p2, DefaultConfig())

	pair, _ := j1.CreateTokens(testSubject, struct{}{})

	_, err := j2.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("token signed by j1 should be invalid for j2, got %v", err)
	}
}

// ---- HashRefreshToken() -----------------------------------------------------

func TestHashRefreshToken_isDeterministic(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	h1 := j.HashRefreshToken(pair.RefreshToken)
	h2 := j.HashRefreshToken(pair.RefreshToken)
	if h1 != h2 {
		t.Errorf("HashRefreshToken is not deterministic: %q != %q", h1, h2)
	}
}

func TestHashRefreshToken_differentTokensDifferentHashes(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	p1, _ := j.CreateTokens(testSubject, struct{}{})
	p2, _ := j.CreateTokens(testSubject, struct{}{})

	if j.HashRefreshToken(p1.RefreshToken) == j.HashRefreshToken(p2.RefreshToken) {
		t.Error("different refresh tokens must produce different HMAC digests")
	}
}

func TestHashRefreshToken_differentSecretsDifferentHashes(t *testing.T) {
	j1 := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	j2 := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())

	// Sign a token with j1's key, hash it with both modules' secrets.
	pair, _ := j1.CreateTokens(testSubject, struct{}{})

	h1 := j1.HashRefreshToken(pair.RefreshToken)
	h2 := j2.HashRefreshToken(pair.RefreshToken)

	// Different HMAC secrets must produce different digests.
	if h1 == h2 {
		t.Error("same token hashed with different secrets should produce different results")
	}
}

// ---- RotateTokens() ---------------------------------------------------------

func TestRotateTokens_returnsNewPairForSameSubject(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	old, _ := j.CreateTokens("0191b432-b5a7-7c4f-b2e6-7a3f1d2e0007", struct{}{})

	newPair, err := j.RotateTokens(old.RefreshToken, struct{}{})
	if err != nil {
		t.Fatalf("RotateTokens() error = %v", err)
	}

	claims, _ := j.VerifyAccessToken(newPair.AccessToken)
	if claims.Subject != "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0007" {
		t.Errorf("Subject after rotation = %q, want %q", claims.Subject, "0191b432-b5a7-7c4f-b2e6-7a3f1d2e0007")
	}
}

func TestRotateTokens_newTokensDifferFromOld(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	old, _ := j.CreateTokens(testSubject, struct{}{})

	// Advance clock by 1 second so the issued-at differs.
	j.clock = clock.Fixed(epoch.Add(time.Second))
	newPair, _ := j.RotateTokens(old.RefreshToken, struct{}{})

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
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens(testSubject, struct{}{})

	// Advance past refresh token TTL.
	j.clock = clock.Fixed(epoch.Add(25 * time.Hour))

	_, err := j.RotateTokens(pair.RefreshToken, struct{}{})
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestRotateTokens_rejectsAccessToken(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	_, err := j.RotateTokens(pair.AccessToken, struct{}{})
	if !errors.Is(err, ErrWrongTokenType) {
		t.Errorf("expected ErrWrongTokenType, got %v", err)
	}
}

func TestRotateTokens_rejectsTamperedToken(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	rt := pair.RefreshToken
	midRT := len(rt) - 10
	origRT := rt[midRT]
	replacementRT := byte('A')
	if origRT == 'A' {
		replacementRT = 'B'
	}
	tampered := rt[:midRT] + string(replacementRT) + rt[midRT+1:]
	_, err := j.RotateTokens(tampered, struct{}{})
	if !errors.Is(err, ErrTokenInvalid) && !errors.Is(err, ErrTokenMalformed) {
		t.Errorf("expected ErrTokenInvalid or ErrTokenMalformed, got %v", err)
	}
}

func TestRotateTokens_newHashMatchesHashRefreshToken(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	j.clock = clock.Fixed(epoch.Add(time.Second))
	newPair, _ := j.RotateTokens(pair.RefreshToken, struct{}{})

	got := j.HashRefreshToken(newPair.RefreshToken)
	if got != newPair.RefreshTokenHash {
		t.Errorf("HashRefreshToken(new token) = %q, want %q", got, newPair.RefreshTokenHash)
	}
}

func TestRotateTokens_preservesSessionID(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	original, _ := j.CreateTokens(testSubject, struct{}{})

	j.clock = clock.Fixed(epoch.Add(time.Second))
	rotated, err := j.RotateTokens(original.RefreshToken, struct{}{})
	if err != nil {
		t.Fatalf("RotateTokens() error = %v", err)
	}
	if rotated.SessionID != original.SessionID {
		t.Errorf("SessionID changed after rotation: got %q, want %q", rotated.SessionID, original.SessionID)
	}
}

// ---- VerifyRefreshTokenHash() -----------------------------------------------

func TestVerifyRefreshTokenHash_matchesStoredHash(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	if !j.VerifyRefreshTokenHash(pair.RefreshToken, pair.RefreshTokenHash) {
		t.Error("VerifyRefreshTokenHash returned false for a valid token/hash pair")
	}
}

func TestVerifyRefreshTokenHash_modifiedTokenDoesNotMatch(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	if j.VerifyRefreshTokenHash(pair.RefreshToken+"X", pair.RefreshTokenHash) {
		t.Error("VerifyRefreshTokenHash returned true for a modified token")
	}
}

func TestVerifyRefreshTokenHash_modifiedHashDoesNotMatch(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	badHash := strings.Repeat("0", 64)
	if j.VerifyRefreshTokenHash(pair.RefreshToken, badHash) {
		t.Error("VerifyRefreshTokenHash returned true for a tampered hash")
	}
}

func TestVerifyRefreshTokenHash_emptyTokenDoesNotMatch(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	if j.VerifyRefreshTokenHash("", pair.RefreshTokenHash) {
		t.Error("VerifyRefreshTokenHash returned true for empty token")
	}
}

func TestVerifyRefreshTokenHash_emptyHashDoesNotMatch(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	if j.VerifyRefreshTokenHash(pair.RefreshToken, "") {
		t.Error("VerifyRefreshTokenHash returned true for empty stored hash")
	}
}

func TestVerifyRefreshTokenHash_consistentWithHashRefreshToken(t *testing.T) {
	j := newTestJWT[struct{}](t, newFakeProvider(t), DefaultConfig())
	pair, _ := j.CreateTokens(testSubject, struct{}{})

	hash := j.HashRefreshToken(pair.RefreshToken)
	if !j.VerifyRefreshTokenHash(pair.RefreshToken, hash) {
		t.Error("VerifyRefreshTokenHash disagrees with HashRefreshToken for the same input")
	}
}

// ---- ClockSkewLeeway --------------------------------------------------------

func TestNew_negativeLeewayReturnsErrInvalidConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ClockSkewLeeway = -1 * time.Second

	_, err := New[struct{}](newFakeProvider(t), cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestVerifyAccessToken_tokenWithinLeewayIsAccepted(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 10 * time.Minute
	cfg.ClockSkewLeeway = 30 * time.Second
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens(testSubject, struct{}{})

	// Advance 20 s past expiry — within the 30 s leeway window.
	j.clock = clock.Fixed(epoch.Add(10*time.Minute + 20*time.Second))
	if _, err := j.VerifyAccessToken(pair.AccessToken); err != nil {
		t.Errorf("token within leeway should be accepted, got %v", err)
	}
}

func TestVerifyAccessToken_tokenBeyondLeewayIsRejected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AccessTokenTTL = 10 * time.Minute
	cfg.ClockSkewLeeway = 30 * time.Second
	j := newTestJWT[struct{}](t, newFakeProvider(t), cfg)

	pair, _ := j.CreateTokens(testSubject, struct{}{})

	// Advance 31 s past expiry — beyond the leeway window.
	j.clock = clock.Fixed(epoch.Add(10*time.Minute + 31*time.Second))
	_, err := j.VerifyAccessToken(pair.AccessToken)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("token beyond leeway should return ErrTokenExpired, got %v", err)
	}
}

// ---- applyDefaults ----------------------------------------------------------

func TestApplyDefaults_zeroTTLsAreFilledFromDefaults(t *testing.T) {
	cfg := Config{
		Issuer:   "my-service",
		Audience: []string{"my-audience"},
		// AccessTokenTTL and RefreshTokenTTL intentionally zero
	}
	j, err := New[struct{}](newFakeProvider(t), cfg)
	if err != nil {
		t.Fatalf("New() with zero TTLs error = %v", err)
	}
	if j.cfg.AccessTokenTTL != DefaultConfig().AccessTokenTTL {
		t.Errorf("AccessTokenTTL not filled: got %v", j.cfg.AccessTokenTTL)
	}
	if j.cfg.RefreshTokenTTL != DefaultConfig().RefreshTokenTTL {
		t.Errorf("RefreshTokenTTL not filled: got %v", j.cfg.RefreshTokenTTL)
	}
}

func TestApplyDefaults_zeroIssuerIsFilledFromDefaults(t *testing.T) {
	cfg := Config{Audience: []string{"x"}}
	j, err := New[struct{}](newFakeProvider(t), cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if j.cfg.Issuer != DefaultConfig().Issuer {
		t.Errorf("Issuer not filled: got %q", j.cfg.Issuer)
	}
}

func TestApplyDefaults_zeroAudienceIsFilledFromDefaults(t *testing.T) {
	cfg := Config{Issuer: "x"}
	j, err := New[struct{}](newFakeProvider(t), cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if len(j.cfg.Audience) == 0 {
		t.Error("Audience not filled from defaults")
	}
}

// ---- TestRotateTokens_freshClaimsEmbeddedInNewAccessToken -------------------

func TestRotateTokens_freshClaimsEmbeddedInNewAccessToken(t *testing.T) {
	j := newTestJWT[testUserClaims](t, newFakeProvider(t), DefaultConfig())
	old, _ := j.CreateTokens(testSubject, testUserClaims{Name: "Juan", Role: "user"})

	j.clock = clock.Fixed(epoch.Add(time.Second))
	fresh := testUserClaims{Name: "Juan", Role: "admin"} // role promoted
	newPair, _ := j.RotateTokens(old.RefreshToken, fresh)

	claims, err := j.VerifyAccessToken(newPair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken() error = %v", err)
	}
	if claims.Extra.Role != "admin" {
		t.Errorf("Extra.Role after rotation = %q, want %q", claims.Extra.Role, "admin")
	}
}
