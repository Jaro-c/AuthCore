package jwt

import "time"

// TokenPair holds the result of a successful token creation or rotation.
// The library never stores tokens — the application is responsible for
// persisting the RefreshTokenHash and associating it with the user.
type TokenPair struct {
	// AccessToken is the short-lived JWT for authenticating API requests.
	// Include this in the Authorization: Bearer header.
	// Default lifetime: 15 minutes.
	AccessToken string

	// AccessTokenID is the UUID v7 that uniquely identifies this access token.
	// It is the "jti" claim embedded in the AccessToken.
	// Use it for audit logging or access token revocation (blocklist by jti).
	AccessTokenID string

	// AccessTokenExpiresAt is when AccessToken expires.
	// Send this to the client so it can schedule a token refresh proactively.
	AccessTokenExpiresAt time.Time

	// RefreshToken is the long-lived JWT for obtaining new access tokens.
	// Store this on the client side in secure, httpOnly storage.
	// Default lifetime: 24 hours.
	RefreshToken string

	// RefreshTokenExpiresAt is when RefreshToken expires.
	// After this time the user must log in again.
	RefreshTokenExpiresAt time.Time

	// RefreshTokenHash is the HMAC-SHA256 hex-encoded digest of RefreshToken.
	//
	// Store ONLY this value in your database — never the raw RefreshToken.
	// When a client presents a refresh token, call HashRefreshToken to
	// compute its hash and look it up in your database before calling
	// RotateTokens.
	RefreshTokenHash string

	// SessionID is the UUID v7 that uniquely identifies this session.
	// It is the "jti" claim embedded in the RefreshToken.
	// Use it as the primary key for your session store to associate
	// metadata such as device, IP address, or last-seen time.
	SessionID string
}

// Claims represents the verified payload extracted from an access token.
// It is returned by VerifyAccessToken after successful signature and
// expiry validation.
type Claims struct {
	// Subject is the "sub" claim — the unique user identifier supplied
	// when CreateTokens was called.
	Subject string

	// Issuer is the "iss" claim as configured in jwt.Config.Issuer.
	Issuer string

	// TokenID is the "jti" claim. Only present in refresh tokens.
	// Empty for access tokens.
	TokenID string

	// IssuedAt is when the token was created (the "iat" claim).
	IssuedAt time.Time

	// ExpiresAt is when the token expires (the "exp" claim).
	ExpiresAt time.Time
}
