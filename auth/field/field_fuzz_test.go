package field

// Fuzz targets for the field module. Two are required: feed arbitrary
// strings to Decrypt and assert it never panics and never returns a
// nil error for a random input, and round trip arbitrary plaintexts
// through Encrypt and Decrypt and assert equality. Modeled on
// auth/credential/credential_fuzz_test.go.

import (
	"encoding/base64"
	"testing"
)

// FuzzDecrypt drives Decrypt with arbitrary input. Decrypt accepts
// ciphertext from the database, so every input is potentially
// adversarial: it must never panic and must never return a nil error
// for a ciphertext the module did not produce. The only path to a
// nil result is a ciphertext that (a) base64-decodes, (b) is at
// least nonce+tag bytes long, and (c) authenticates against the
// AAD the module was built with. The fuzzer can construct (a) and
// (b) but not (c) without breaking AES-GCM.
func FuzzDecrypt(f *testing.F) {
	mod, err := New(newFakeProvider(f), Config{Context: "email"})
	if err != nil {
		f.Fatalf("field.New: %v", err)
	}

	// Seed corpus: empty, a few shapes that should fail (too
	// short, bad base64), and a tampered ciphertext that should
	// still fail. We deliberately do NOT seed the happy-path
	// ciphertext the module just produced, because the fuzz body
	// treats any nil result as a failure and the only path to
	// nil is a ciphertext the module minted. The fuzzer cannot
	// reconstruct that without the AES key.
	ct, err := mod.Encrypt("alice@example.com")
	if err != nil {
		f.Fatalf("Encrypt: %v", err)
	}
	raw, _ := base64.RawStdEncoding.DecodeString(ct)
	tampered := make([]byte, len(raw))
	copy(tampered, raw)
	tampered[len(tampered)-1] ^= 0xFF

	f.Add("")
	f.Add("!")
	f.Add("abc")
	f.Add(base64.RawStdEncoding.EncodeToString(tampered))
	f.Add(base64.RawStdEncoding.EncodeToString([]byte{1, 2, 3}))
	f.Add("====not base64====")
	f.Add("eA") // a real base64 string of 1 byte

	f.Fuzz(func(t *testing.T, ciphertext string) {
		// Decrypt must never panic. Returning ErrDecrypt is the
		// expected outcome for every seed; the only path to a
		// non-error result is a ciphertext the module produced
		// under the same context, which the fuzzer cannot
		// reconstruct without the AES key.
		pt, err := mod.Decrypt(ciphertext)
		if err == nil {
			t.Fatalf("Decrypt accepted adversarial input %q (got %q)", ciphertext, pt)
		}
	})
}

// FuzzEncryptDecrypt drives Encrypt and Decrypt in sequence with
// arbitrary input. The encrypt path draws a fresh nonce and seals;
// the decrypt path must hand back the exact bytes the caller
// produced. Every byte sequence must round trip because the AAD
// only depends on the bound Context, not the plaintext.
func FuzzEncryptDecrypt(f *testing.F) {
	mod, err := New(newFakeProvider(f), Config{Context: "email"})
	if err != nil {
		f.Fatalf("field.New: %v", err)
	}

	// Seed corpus: empty, ASCII, multibyte UTF-8, embedded NUL,
	// invalid UTF-8 byte sequences, and a long string to stress
	// the seal buffers.
	f.Add("")
	f.Add("alice@example.com")
	f.Add("a\x00b")
	f.Add("\xff\xfe\xfd")
	f.Add("\x00")
	f.Add("éèêë 中文 🎉")
	f.Add(string([]byte{0xC3, 0x28, 0xFE, 0xFF}))

	f.Fuzz(func(t *testing.T, plaintext string) {
		ct, err := mod.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt(%q) returned error: %v", plaintext, err)
		}
		pt, err := mod.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt(Encrypt(%q)) returned error: %v", plaintext, err)
		}
		if pt != plaintext {
			t.Fatalf("round trip mismatch: Encrypt(%q) -> Decrypt -> %q", plaintext, pt)
		}
	})
}
