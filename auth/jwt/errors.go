package jwt

import "errors"

// Sentinel errors returned by the jwt package.
// Use errors.Is to check for these in calling code.
var (
	// ErrInvalidConfig is returned when jwt.Config fails validation.
	ErrInvalidConfig = errors.New("jwt: invalid configuration")

	// ErrTokenExpired is returned when a token's exp claim is in the past.
	ErrTokenExpired = errors.New("jwt: token has expired")

	// ErrTokenInvalid is returned when the token signature does not verify,
	// or when an unsupported algorithm is present in the JOSE header.
	ErrTokenInvalid = errors.New("jwt: token is invalid")

	// ErrTokenMalformed is returned when the token is not a properly formed
	// three-part dot-separated string, or when any part cannot be base64url-decoded.
	ErrTokenMalformed = errors.New("jwt: token is malformed")

	// ErrWrongTokenType is returned when an access token is passed to a
	// function that expects a refresh token, or vice-versa.
	ErrWrongTokenType = errors.New("jwt: wrong token type")

	// ErrInvalidSubject is returned when CreateTokens is called with a
	// subject that is not a valid UUID (any version, case-insensitive).
	ErrInvalidSubject = errors.New("jwt: subject must be a valid UUID")
)
