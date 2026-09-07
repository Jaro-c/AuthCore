package username

import "errors"

// ErrInvalidUsername signals that a username failed validation.
//
// CLIENT-SAFE: the wrapped reason describes exactly which rule failed and is
// suitable for returning in a 400 response:
//
//	normalized, err := usernameMod.ValidateAndNormalize(req.Username)
//	if err != nil {
//	    c.JSON(400, map[string]string{"error": errors.Unwrap(err).Error()})
//	    return
//	}
//
// Use errors.Is to check for this in calling code.
var ErrInvalidUsername = errors.New("username: invalid username")

// ErrInvalidConfig is returned by NewWithConfig when the provided Config
// fails validation (for example, MinLength < 1). This is a programming or
// startup error - it should never reach an HTTP handler.
//
// Safety: INTERNAL - do not expose to clients. Treat as a 500.
var ErrInvalidConfig = errors.New("username: invalid config")

// usernameViolation wraps ErrInvalidUsername with a single specific reason so
// that both errors.Is(err, ErrInvalidUsername) and errors.Unwrap(err) work correctly.
// Using fmt.Errorf("%w: %w", ...) would create a multi-unwrap error in Go 1.20+
// where errors.Unwrap returns nil, breaking the errors.Unwrap(err).Error() pattern.
type usernameViolation struct{ reason error }

func (v *usernameViolation) Error() string {
	return ErrInvalidUsername.Error() + ": " + v.reason.Error()
}
func (v *usernameViolation) Is(t error) bool { return t == ErrInvalidUsername }
func (v *usernameViolation) Unwrap() error   { return v.reason }

// configViolation wraps ErrInvalidConfig with the underlying reason. Same
// pattern as usernameViolation: a single wrapped error so errors.Unwrap
// returns the specific cause.
type configViolation struct{ reason error }

func (v *configViolation) Error() string {
	return ErrInvalidConfig.Error() + ": " + v.reason.Error()
}
func (v *configViolation) Is(t error) bool { return t == ErrInvalidConfig }
func (v *configViolation) Unwrap() error   { return v.reason }
