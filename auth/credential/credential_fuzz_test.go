package credential

// Fuzz target for Verify. Verify accepts purpose, subject, token and
// storedHash from the network (or from the caller's storage), so every
// input is potentially adversarial. issuedAt is held at a fixed instant
// inside the TTL window so a nil result is never expected regardless of
// the string inputs - the only valid match would have to be the exact
// purpose, subject and token we minted ourselves, which the seed corpus
// covers in one case and the fuzzer cannot reach by construction.
//
// Verify must never panic and must never report a successful match for
// any input the module did not mint. Modeled on auth/totp/totp_fuzz_test.go.

import (
	"testing"

	"github.com/Glyndor/authcore/internal/clock"
)

func FuzzVerify(f *testing.F) {
	mod, err := New(newFakeProvider(f))
	if err != nil {
		f.Fatalf("credential.New: %v", err)
	}
	mod.clock = clock.Fixed(epoch)

	// Seed with adversarial inputs only. We do not seed a tuple that
	// matches the Issue we just minted because the fuzz body treats
	// any nil result as a failure - the only path to a nil result is
	// a successful match against the freshly-minted (Token, Hash),
	// which only happens for that specific tuple. The fuzzer cannot
	// reconstruct it from random bytes.
	enr, err := mod.Issue("reset", "alice@example.com")
	if err != nil {
		f.Fatalf("Issue: %v", err)
	}
	// Use the freshly-minted Token and Hash but with a mismatched
	// (purpose, subject, hash) so every seed must fail.
	f.Add("activate", "alice@example.com", enr.Token, enr.Hash)
	f.Add("reset", "bob@example.com", enr.Token, enr.Hash)
	f.Add("reset", "alice@example.com", "", "")
	f.Add("", "", "", "")
	f.Add("reset", "alice@example.com", "\x00\x00\x00", "deadbeef")
	f.Add("reset", "alice@example.com", enr.Token, enr.Hash[:60]) // truncated hash
	f.Add("reset", "alice@example.com", enr.Token, "")            // empty stored hash
	f.Add("reset", "alice@example.com", "short", enr.Hash)        // wrong token

	f.Fuzz(func(t *testing.T, purpose, subject, token, storedHash string) {
		// issuedAt is pinned to epoch (inside TTL) so the only path to
		// a nil result is a successful match against enr.Hash, which
		// only happens for the (reset, alice@example.com, enr.Token)
		// tuple. The fuzzer cannot reconstruct that tuple from random
		// bytes: it would need to break HMAC-SHA256 with the pepper
		// this module was initialised with.
		err := mod.Verify(purpose, subject, token, storedHash, epoch)
		if err == nil {
			t.Fatalf("Verify accepted adversarial input (purpose=%q subject=%q token=%q hash=%q)",
				purpose, subject, token, storedHash)
		}
	})
}
