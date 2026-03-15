// Package jwt provides JSON Web Token (JWT) authentication for authcore.
//
// Tokens are signed with Ed25519 (alg=EdDSA) using keys managed by authcore's
// key manager. Token encoding is handled by github.com/golang-jwt/jwt/v5.
//
// # Token strategy
//
// Two token kinds are issued:
//
//   - Access token  — short-lived (default 15 min), sent in Authorization: Bearer.
//   - Refresh token — long-lived  (default 24 h),  stored securely by the client.
//
// # Custom claims
//
// JWT is generic over T, which holds application-specific fields embedded
// in the access token payload under the "extra" key. The refresh token never
// carries custom claims.
//
//	type UserClaims struct {
//	    Name string `json:"name"`
//	    Role string `json:"role"`
//	}
//
//	jwtMod, _ := jwt.New[UserClaims](auth, jwt.DefaultConfig())
//
// # Storage model
//
// The library is storage-agnostic. It returns a hashed form of the refresh
// token that the application stores in its database. The raw token is never
// persisted by the library.
//
// # Typical server-side flow
//
//	// 1. Initialise once at startup.
//	auth, _    := authcore.New(authcore.DefaultConfig())
//	jwtMod, _ := jwt.New[UserClaims](auth, jwt.DefaultConfig())
//
//	// 2. Login — create a token pair for the authenticated user.
//	pair, _ := jwtMod.CreateTokens(userID, UserClaims{Name: "Ana", Role: "admin"})
//	sendToBrowser(pair.AccessToken, pair.RefreshToken)
//	db.StoreRefreshHash(userID, pair.RefreshTokenHash)
//
//	// 3. Authenticated request — verify the access token on each call.
//	claims, err := jwtMod.VerifyAccessToken(accessToken)
//	if err != nil { ... } // errors.Is(err, jwt.ErrTokenExpired)
//	fmt.Println(claims.Extra.Name)
//
//	// 4. Token rotation — verify the hash first (timing-safe), then rotate.
//	if !jwtMod.VerifyRefreshTokenHash(clientToken, storedHash) {
//	    return http.StatusUnauthorized
//	}
//	user, _ := db.GetUser(userID)
//	newPair, _ := jwtMod.RotateTokens(clientToken, UserClaims{Name: user.Name, Role: user.Role})
//	db.ReplaceRefreshHash(storedHash, newPair.RefreshTokenHash)
//	sendToBrowser(newPair.AccessToken, newPair.RefreshToken)
package jwt

import (
	"crypto/ed25519"
	"crypto/subtle"
	"fmt"
	"regexp"
	"strings"

	"github.com/Jaro-c/authcore"
	"github.com/Jaro-c/authcore/internal/clock"
)

// uuidRe matches UUID v7 in canonical form (case-insensitive via ToLower).
// Position 14 (version digit) must be 7 (RFC 9562 §5.7).
// Position 19 (variant byte) must be 8, 9, a, or b (RFC 4122 variant).
var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Compile-time assertion: *JWT[struct{}] must satisfy authcore.Module.
var _ authcore.Module = (*JWT[struct{}])(nil)

// JWT is the authentication module for JSON Web Tokens.
//
// T is the application-specific type embedded in access token payloads under
// the "extra" key. Use struct{} if no custom claims are needed.
//
// Construct one instance at application startup using New and share it
// across all goroutines. JWT is safe for concurrent use after construction.
type JWT[T any] struct {
	cfg    Config
	log    authcore.Logger
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	secret []byte      // HMAC-SHA256 key for hashing refresh tokens
	kid    string      // JOSE "kid" header value, derived from the public key
	clock  clock.Clock // injected; replaced by clock.Fixed in tests
}

// New creates and returns a JWT module.
//
// T is the application-specific claims type embedded in access tokens.
// Use struct{} if no custom claims are needed:
//
//	jwtMod, err := jwt.New[struct{}](auth, jwt.DefaultConfig())
//
// p provides the Ed25519 signing keys, the HMAC secret, the logger, and the
// timezone — all sourced from the parent AuthCore instance.
// cfg controls token lifetimes and the issuer claim.
func New[T any](p authcore.Provider, cfg Config) (*JWT[T], error) {
	cfg = applyDefaults(cfg)

	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	j := &JWT[T]{
		cfg:    cfg,
		log:    p.Logger(),
		priv:   p.Keys().PrivateKey(),
		pub:    p.Keys().PublicKey(),
		secret: p.Keys().RefreshSecret(),
		kid:    p.Keys().KeyID(),
		clock:  clock.New(p.Config().Timezone),
	}

	j.log.Info("jwt: module initialised (issuer=%s, access_ttl=%s, refresh_ttl=%s)",
		cfg.Issuer, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)

	return j, nil
}

// Name returns the module's unique identifier. It implements authcore.Module.
func (j *JWT[T]) Name() string { return "jwt" }

// CreateTokens generates a new access and refresh token pair for subject.
//
// subject is the UUID v7 that identifies the user in your system. It is stored
// in the "sub" JWT claim and returned in Claims.Subject after verification.
// Only UUID v7 is accepted (RFC 9562 §5.7); any casing is allowed — the value
// is normalised to lowercase before signing.
//
// extra holds the application-specific claims embedded in the access token
// under the "extra" key. Use struct{}{} if no custom claims are needed.
// The refresh token never carries extra claims.
//
// The returned TokenPair contains:
//
//	pair.AccessToken           — include in Authorization: Bearer on API requests
//	pair.AccessTokenExpiresAt  — send to the client to schedule proactive renewal
//	pair.RefreshToken          — store in a secure, httpOnly client-side location
//	pair.RefreshTokenExpiresAt — when the user must log in again
//	pair.RefreshTokenHash      — store in your database; never store the raw token
//	pair.SessionID             — UUID v7 jti shared by both tokens; primary key for session store
//
// The access token's individual jti is available as claims.TokenID after VerifyAccessToken.
//
// The library does not persist any of these values.
func (j *JWT[T]) CreateTokens(subject string, extra T) (*TokenPair, error) {
	subject = strings.ToLower(subject)
	if !uuidRe.MatchString(subject) {
		return nil, ErrInvalidSubject
	}

	now := j.clock.Now()

	// Both tokens share the same JTI — it identifies the session.
	jti, err := generateJTI(now)
	if err != nil {
		return nil, err
	}

	// ----- Access token -----
	accessToken, err := signToken(newAccessClaims(j.cfg.Issuer, subject, jti, j.cfg.Audience, extra, now, j.cfg.AccessTokenTTL), j.priv, j.kid)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	// ----- Refresh token (no extra) -----
	refreshToken, err := signToken(newRefreshClaims(j.cfg.Issuer, subject, jti, j.cfg.Audience, now, j.cfg.RefreshTokenTTL), j.priv, j.kid)
	if err != nil {
		return nil, fmt.Errorf("sign refresh token: %w", err)
	}

	j.log.Debug("jwt: token pair created (sub=%s, jti=%s)", subject, jti)

	return &TokenPair{
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  now.Add(j.cfg.AccessTokenTTL),
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: now.Add(j.cfg.RefreshTokenTTL),
		RefreshTokenHash:      computeHMAC(refreshToken, j.secret),
		SessionID:             jti,
	}, nil
}

// VerifyAccessToken parses and validates an access token string.
//
// On success it returns the verified Claims extracted from the token payload,
// including the application-specific Extra fields.
// On failure it returns one of the following sentinel errors:
//
//	jwt.ErrTokenExpired   — exp claim is in the past
//	jwt.ErrTokenInvalid   — signature invalid or unsupported algorithm
//	jwt.ErrTokenMalformed — not a valid three-part JWT string
//	jwt.ErrWrongTokenType — token is a refresh token, not an access token
//
// Use errors.Is for error inspection:
//
//	claims, err := jwtMod.VerifyAccessToken(token)
//	if errors.Is(err, jwt.ErrTokenExpired) { ... }
func (j *JWT[T]) VerifyAccessToken(token string) (*Claims[T], error) {
	c, err := verifyAccessToken[T](token, j.pub, j.clock.Now(), j.cfg.Audience, j.cfg.ClockSkewLeeway)
	if err != nil {
		return nil, err
	}
	if c.Type != tokenTypeAccess {
		return nil, ErrWrongTokenType
	}
	return accessClaimsToClaims(c), nil
}

// HashRefreshToken returns the HMAC-SHA256 hex digest of the given token
// string using the library's managed refresh secret.
//
// Use this to derive the database lookup key before calling RotateTokens:
//
//	hash := jwtMod.HashRefreshToken(clientToken)
//	row, err := db.FindByHash(hash)
//	if err != nil { return http.StatusUnauthorized }
//	newPair, err := jwtMod.RotateTokens(clientToken, freshClaims)
func (j *JWT[T]) HashRefreshToken(token string) string {
	return computeHMAC(token, j.secret)
}

// VerifyRefreshTokenHash reports whether token produces the same HMAC-SHA256
// digest as storedHash using a constant-time comparison to prevent timing attacks.
//
// Call this instead of a plain string equality check when validating a client's
// refresh token against the hash stored in your database:
//
//	if !jwtMod.VerifyRefreshTokenHash(clientToken, row.RefreshTokenHash) {
//	    return http.StatusUnauthorized
//	}
//	newPair, err := jwtMod.RotateTokens(clientToken, freshClaims)
func (j *JWT[T]) VerifyRefreshTokenHash(token, storedHash string) bool {
	computed := computeHMAC(token, j.secret)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(storedHash)) == 1
}

// RotateTokens verifies refreshToken, then generates and returns a new
// token pair for the same subject with fresh extra claims.
//
// Because the refresh token does not carry application-specific data, the
// caller must supply updated extra claims (typically re-fetched from the
// database at rotation time).
//
// After a successful rotation, the old refresh token MUST be considered
// invalid. The application must replace the stored hash atomically:
//
//	db.ReplaceRefreshHash(oldHash, newPair.RefreshTokenHash)
//
// This function validates the token's signature and expiry but does NOT check
// whether the hash exists in a database — that is the application's responsibility
// and must happen before calling RotateTokens.
//
// Returns the same errors as VerifyAccessToken.
func (j *JWT[T]) RotateTokens(refreshToken string, extra T) (*TokenPair, error) {
	c, err := verifyRefreshToken(refreshToken, j.pub, j.clock.Now(), j.cfg.Audience, j.cfg.ClockSkewLeeway)
	if err != nil {
		return nil, err
	}
	if c.Type != tokenTypeRefresh {
		return nil, ErrWrongTokenType
	}

	j.log.Debug("jwt: rotating token (sub=%s, old_jti=%s)", c.Subject, c.ID)

	return j.CreateTokens(c.Subject, extra)
}
