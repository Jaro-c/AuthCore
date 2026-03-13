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
//	jwtMod, _ := jwt.New(auth, jwt.DefaultConfig())
//
//	// 2. Login — create a token pair for the authenticated user.
//	pair, _ := jwtMod.CreateTokens(userID)
//	sendToBrowser(pair.AccessToken, pair.RefreshToken)
//	db.StoreRefreshHash(userID, pair.RefreshTokenHash)
//
//	// 3. Authenticated request — verify the access token on each call.
//	claims, err := jwtMod.VerifyAccessToken(accessToken)
//	if err != nil { ... } // errors.Is(err, jwt.ErrTokenExpired)
//
//	// 4. Token rotation — when the client presents a refresh token.
//	oldHash := jwtMod.HashRefreshToken(clientToken)
//	if !db.Exists(oldHash) { return http.StatusUnauthorized }
//	newPair, _ := jwtMod.RotateTokens(clientToken)
//	db.ReplaceRefreshHash(oldHash, newPair.RefreshTokenHash)
//	sendToBrowser(newPair.AccessToken, newPair.RefreshToken)
package jwt

import (
	"crypto/ed25519"
	"fmt"
	"regexp"
	"strings"

	"github.com/Jaro-c/authcore"
	"github.com/Jaro-c/authcore/internal/clock"
)

// uuidRe matches UUID v4 and v7 in canonical form (case-insensitive via ToLower).
// Position 14 (version digit) must be 4 or 7.
// Position 19 (variant byte) must be 8, 9, a, or b (RFC 4122 variant).
var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// Compile-time assertion: *JWT must satisfy authcore.Module.
var _ authcore.Module = (*JWT)(nil)

// JWT is the authentication module for JSON Web Tokens.
//
// Construct one instance at application startup using New and share it
// across all goroutines. JWT is safe for concurrent use after construction.
type JWT struct {
	cfg    Config
	log    authcore.Logger
	priv   ed25519.PrivateKey
	pub    ed25519.PublicKey
	secret []byte      // HMAC-SHA256 key for hashing refresh tokens
	clock  clock.Clock // injected; replaced by clock.Fixed in tests
}

// New creates and returns a JWT module.
//
// p provides the Ed25519 signing keys, the HMAC secret, the logger, and the
// timezone — all sourced from the parent AuthCore instance.
// cfg controls token lifetimes and the issuer claim.
//
//	jwtMod, err := jwt.New(auth, jwt.DefaultConfig())
//	if err != nil { log.Fatal(err) }
func New(p authcore.Provider, cfg Config) (*JWT, error) {
	cfg = applyDefaults(cfg)

	if err := validateConfig(cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	j := &JWT{
		cfg:    cfg,
		log:    p.Logger(),
		priv:   p.Keys().PrivateKey(),
		pub:    p.Keys().PublicKey(),
		secret: p.Keys().RefreshSecret(),
		clock:  clock.New(p.Config().Timezone),
	}

	j.log.Info("jwt: module initialised (issuer=%s, access_ttl=%s, refresh_ttl=%s)",
		cfg.Issuer, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)

	return j, nil
}

// Name returns the module's unique identifier. It implements authcore.Module.
func (j *JWT) Name() string { return "jwt" }

// CreateTokens generates a new access and refresh token pair for subject.
//
// subject is the UUID that identifies the user in your system. It is stored
// in the "sub" JWT claim and returned in Claims.Subject after verification.
// Any UUID version is accepted (v4, v7, etc.) and any casing — the value is
// normalised to lowercase before signing.
//
// The returned TokenPair contains:
//
//	pair.AccessToken           — include in Authorization: Bearer on API requests
//	pair.AccessTokenExpiresAt  — send to the client to schedule proactive renewal
//	pair.RefreshToken          — store in a secure, httpOnly client-side location
//	pair.RefreshTokenExpiresAt — when the user must log in again
//	pair.RefreshTokenHash      — store in your database; never store the raw token
//
// The library does not persist any of these values.
func (j *JWT) CreateTokens(subject string) (*TokenPair, error) {
	subject = strings.ToLower(subject)
	if !uuidRe.MatchString(subject) {
		return nil, ErrInvalidSubject
	}

	now := j.clock.Now()

	// ----- Access token (no jti — short-lived, not tracked by the DB) -----
	accessToken, err := signToken(newAccessClaims(j.cfg.Issuer, subject, now, j.cfg.AccessTokenTTL), j.priv)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	// ----- Refresh token (carries a jti for rotation tracking) -----
	jti, err := generateJTI()
	if err != nil {
		return nil, err
	}
	refreshToken, err := signToken(newRefreshClaims(j.cfg.Issuer, subject, jti, now, j.cfg.RefreshTokenTTL), j.priv)
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
	}, nil
}

// VerifyAccessToken parses and validates an access token string.
//
// On success it returns the verified Claims extracted from the token payload.
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
func (j *JWT) VerifyAccessToken(token string) (*Claims, error) {
	c, err := verifyToken(token, j.pub, j.clock.Now())
	if err != nil {
		return nil, err
	}
	if c.Type != tokenTypeAccess {
		return nil, ErrWrongTokenType
	}
	return claimsToClaims(c), nil
}

// HashRefreshToken returns the HMAC-SHA256 hex digest of the given token
// string using the library's managed refresh secret.
//
// Use this to derive the database lookup key before calling RotateTokens:
//
//	hash := jwtMod.HashRefreshToken(clientToken)
//	row, err := db.FindByHash(hash)
//	if err != nil { return http.StatusUnauthorized }
//	newPair, err := jwtMod.RotateTokens(clientToken)
func (j *JWT) HashRefreshToken(token string) string {
	return computeHMAC(token, j.secret)
}

// RotateTokens verifies refreshToken, then generates and returns a new
// token pair for the same subject.
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
func (j *JWT) RotateTokens(refreshToken string) (*TokenPair, error) {
	c, err := verifyToken(refreshToken, j.pub, j.clock.Now())
	if err != nil {
		return nil, err
	}
	if c.Type != tokenTypeRefresh {
		return nil, ErrWrongTokenType
	}

	j.log.Debug("jwt: rotating token (sub=%s, old_jti=%s)", c.Subject, c.ID)

	return j.CreateTokens(c.Subject)
}
