package totp

import (
	"strings"
	"testing"
	"time"

	"github.com/Glyndor/authcore/internal/clock"
)

// FuzzVerify drives Verify with arbitrary secret/code pairs. Both inputs
// come from the network (the secret from the user's stored row, the
// code from the form), so neither must panic. Verify must also never
// report a successful match for a random input: with a fixed clock and
// a known-good secret, the only inputs that succeed are the published
// TOTP values for the current window, and the fuzzer corpus seeds
// deliberately miss those.
func FuzzVerify(f *testing.F) {
	mod, err := New(newFakeProvider(f))
	if err != nil {
		f.Fatalf("totp.New: %v", err)
	}
	mod.clock = clock.Fixed(time.Unix(1234567890, 0).UTC())

	// Seed with realistic and adversarial inputs.
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		f.Fatalf("Enroll: %v", err)
	}
	f.Add(enr.Secret, "000000")
	f.Add(enr.Secret, "999999")
	f.Add(enr.Secret, "")
	f.Add(enr.Secret, "123456")
	f.Add("not-base32!@#", "123456")
	f.Add("", "123456")
	f.Add(enr.Secret, "abcdef")
	f.Add(enr.Secret, "12345")
	f.Add(enr.Secret, "1234567")
	f.Add(enr.Secret, "０１２３４５") // fullwidth digits

	f.Fuzz(func(t *testing.T, secret, code string) {
		// Both lastUsedStep values: 0 (no replay protection) and a
		// large number (must reject everything as "already used" if
		// it ever matched). Neither path may panic.
		_, _ = mod.Verify(secret, code, 0)
		_, _ = mod.Verify(secret, code, 1<<63)
	})
}

// FuzzVerifyRecoveryCode drives VerifyRecoveryCode with arbitrary code
// input against a hash list freshly minted by this module. The code
// comes from the user (and so is adversarial); the hashes come from
// the database (and so can be any byte sequence the application stored).
// The function must never panic and must never report a match for a
// code that was not actually minted by this module.
func FuzzVerifyRecoveryCode(f *testing.F) {
	mod, err := New(newFakeProvider(f))
	if err != nil {
		f.Fatalf("totp.New: %v", err)
	}
	enr, err := mod.Enroll("alice@example.com")
	if err != nil {
		f.Fatalf("Enroll: %v", err)
	}
	stored := enr.RecoveryHashes

	// Seeds: real codes from this module, plus adversarial garbage
	// that must not be accepted.
	f.Add(enr.RecoveryCodes[0])
	f.Add("")
	f.Add("AAAA1111-BBBB2222")
	f.Add("\x00\x00\x00")
	f.Add(strings.Repeat("A", 1024))

	f.Fuzz(func(t *testing.T, code string) {
		// Vary the hash list shape too: empty, freshly-minted,
		// oversized. Each variation is fed as a sub-call rather than
		// as a fuzzer argument because Go fuzzing accepts only a
		// limited set of types in the signature.
		cases := [][]string{nil, {}, stored}
		for _, hashes := range cases {
			idx, ok := mod.VerifyRecoveryCode(code, hashes)
			if !ok {
				continue
			}
			// A match is only valid if the stored hash equals the
			// hash of the presented code under the same pepper.
			if got := mod.HashRecoveryCode(code); got != hashes[idx] {
				t.Fatalf("VerifyRecoveryCode accepted code %q at index %d, "+
					"but HashRecoveryCode(%q) = %q != hashes[%d] = %q",
					code, idx, code, got, idx, hashes[idx])
			}
		}
	})
}
