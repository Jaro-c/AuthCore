package jwt

// token.go contains the internal JWT implementation backed by github.com/golang-jwt/jwt/v5.
//
// Token format (RFC 7519 / RFC 8037 EdDSA):
//
//	BASE64URL(header) + "." + BASE64URL(payload) + "." + BASE64URL(signature)
//
// Header  : {"alg":"EdDSA","typ":"JWT"}
// Payload : JSON object with registered + private claims
// Signature: Ed25519 signature over the raw "header.payload" ASCII bytes

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
)

// tokenTypeAccess and tokenTypeRefresh are the values of the private "type"
// claim used to distinguish the two token kinds at verification time.
const (
	tokenTypeAccess  = "access"
	tokenTypeRefresh = "refresh"
)

// authClaims extends the standard RegisteredClaims with a private "type" claim
// that distinguishes access tokens from refresh tokens.
type authClaims struct {
	gjwt.RegisteredClaims
	Type string `json:"type"` // "access" | "refresh"
}

// newAccessClaims builds the claim set for an access token.
func newAccessClaims(issuer, subject, jti string, now time.Time, ttl time.Duration) *authClaims {
	return &authClaims{
		RegisteredClaims: gjwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			ID:        jti,
			IssuedAt:  gjwt.NewNumericDate(now),
			ExpiresAt: gjwt.NewNumericDate(now.Add(ttl)),
		},
		Type: tokenTypeAccess,
	}
}

// newRefreshClaims builds the claim set for a refresh token.
func newRefreshClaims(issuer, subject, jti string, now time.Time, ttl time.Duration) *authClaims {
	return &authClaims{
		RegisteredClaims: gjwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			ID:        jti,
			IssuedAt:  gjwt.NewNumericDate(now),
			ExpiresAt: gjwt.NewNumericDate(now.Add(ttl)),
		},
		Type: tokenTypeRefresh,
	}
}

// signToken encodes claims as a signed EdDSA JWT and returns the compact serialisation.
// kid is embedded in the JOSE header so verifiers can select the correct public key.
func signToken(claims *authClaims, key ed25519.PrivateKey, kid string) (string, error) {
	token := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

// verifyToken validates the compact JWT string and returns the decoded claims.
// now is injected to allow deterministic testing via clock.Fixed.
func verifyToken(tokenStr string, pub ed25519.PublicKey, now time.Time) (*authClaims, error) {
	var c authClaims
	_, err := gjwt.ParseWithClaims(
		tokenStr, &c,
		func(t *gjwt.Token) (any, error) {
			if _, ok := t.Method.(*gjwt.SigningMethodEd25519); !ok {
				return nil, fmt.Errorf("%w: unexpected alg %q", ErrTokenInvalid, t.Header["alg"])
			}
			return pub, nil
		},
		gjwt.WithTimeFunc(func() time.Time { return now }),
		gjwt.WithExpirationRequired(),
		gjwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, mapJWTError(err)
	}
	return &c, nil
}

// mapJWTError converts golang-jwt sentinel errors to our public sentinels.
func mapJWTError(err error) error {
	switch {
	case errors.Is(err, gjwt.ErrTokenExpired):
		return ErrTokenExpired
	case errors.Is(err, gjwt.ErrTokenSignatureInvalid):
		return ErrTokenInvalid
	case errors.Is(err, gjwt.ErrTokenMalformed):
		return ErrTokenMalformed
	default:
		return fmt.Errorf("%w: %w", ErrTokenInvalid, err)
	}
}

// claimsToClaims converts internal authClaims to the public Claims type.
func claimsToClaims(c *authClaims) *Claims {
	var iat, exp time.Time
	if c.IssuedAt != nil {
		iat = c.IssuedAt.Time
	}
	if c.ExpiresAt != nil {
		exp = c.ExpiresAt.Time
	}
	return &Claims{
		Subject:   c.Subject,
		Issuer:    c.Issuer,
		TokenID:   c.ID,
		IssuedAt:  iat.UTC(),
		ExpiresAt: exp.UTC(),
	}
}

// computeHMAC returns the HMAC-SHA256 hex digest of token keyed with secret.
func computeHMAC(token string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

// generateJTI returns a UUID v7 string suitable for use as the "jti" claim
// in refresh tokens. The 48-bit timestamp comes from now; the remaining bits
// are cryptographically random.
//
// Format: xxxxxxxx-xxxx-7xxx-[89ab]xxx-xxxxxxxxxxxx (RFC 9562 §5.7)
func generateJTI(now time.Time) (string, error) {
	ms := now.UnixMilli()

	var b [16]byte
	// Bytes 0-5: 48-bit Unix timestamp in milliseconds.
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)

	// Bytes 6-15: random.
	if _, err := rand.Read(b[6:]); err != nil {
		return "", fmt.Errorf("generate token ID: %w", err)
	}

	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10xx (RFC 4122)

	h := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]), nil
}
