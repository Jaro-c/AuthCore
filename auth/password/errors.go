package password

import "errors"

// ErrInvalidConfig is returned by New when the provided Config fails validation.
var ErrInvalidConfig = errors.New("password: invalid config")

// ErrInvalidHash is returned by Verify when the stored hash is not a valid
// Argon2id PHC string produced by this module.
var ErrInvalidHash = errors.New("password: invalid hash format")
