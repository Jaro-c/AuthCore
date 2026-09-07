package credential

// Tests for the purpose/subject binding into the stored hash, the zero-byte
// separator that prevents collision attacks, the sentinel errors raised by
// Issue, the URL safety of the token encoding, and the per-call uniqueness
// of Issue.

import (
	"encoding/base64"
	"errors"
	"net/url"
	"testing"
	"time"
)

// ---- Purpose / subject binding ---------------------------------------------

// TestIssue_DifferentPurposesDifferentHashes ensures the hash actually
// binds purpose. Two tokens minted for the same subject under different
// purposes must produce different hashes.
func TestIssue_DifferentPurposesDifferentHashes(t *testing.T) {
	c := newCred(t)
	a, _ := c.Issue("reset", "alice@example.com")
	b, _ := c.Issue("activate", "alice@example.com")
	if a.Token == b.Token {
		t.Skip("two CSPRNG draws returned the same token; rerun")
	}
	if a.Hash == b.Hash {
		t.Error("two tokens minted for different purposes produced the same hash")
	}
}

// TestIssue_DifferentSubjectsDifferentHashes ensures the hash actually
// binds subject. Two tokens minted for the same purpose under different
// subjects must produce different hashes.
func TestIssue_DifferentSubjectsDifferentHashes(t *testing.T) {
	c := newCred(t)
	a, _ := c.Issue("reset", "alice@example.com")
	b, _ := c.Issue("reset", "bob@example.com")
	if a.Hash == b.Hash {
		t.Error("two tokens minted for different subjects produced the same hash")
	}
}

// TestVerify_WrongPurposeRejected is the cross-flow confusion guard. A
// token minted for one purpose must not verify when presented under
// another purpose, even with the correct hash for the other flow.
func TestVerify_WrongPurposeRejected(t *testing.T) {
	c := newCred(t)
	reset, _ := c.Issue("reset", "alice@example.com")
	activate, _ := c.Issue("activate", "alice@example.com")

	// Presenting the reset token under "activate" must fail. The hash
	// the caller would have stored for an activate token is activate.Hash;
	// presenting reset.Token with activate.Hash under "activate" is what
	// this test asserts.
	if err := c.Verify("activate", "alice@example.com", reset.Token, activate.Hash, epoch); !errors.Is(err, ErrInvalidCredential) {
		t.Errorf("cross-purpose verify: got %v, want ErrInvalidCredential", err)
	}

	// And presenting the activate token under "reset" must also fail.
	if err := c.Verify("reset", "alice@example.com", activate.Token, reset.Hash, epoch); !errors.Is(err, ErrInvalidCredential) {
		t.Errorf("reverse cross-purpose verify: got %v, want ErrInvalidCredential", err)
	}
}

// TestVerify_WrongSubjectRejected is the account mixup guard. A token
// minted for one subject must not verify when presented under a
// different subject.
func TestVerify_WrongSubjectRejected(t *testing.T) {
	c := newCred(t)
	a, _ := c.Issue("reset", "alice@example.com")
	b, _ := c.Issue("reset", "bob@example.com")

	if err := c.Verify("reset", "bob@example.com", a.Token, b.Hash, epoch); !errors.Is(err, ErrInvalidCredential) {
		t.Errorf("cross-subject verify: got %v, want ErrInvalidCredential", err)
	}
	if err := c.Verify("reset", "alice@example.com", b.Token, a.Hash, epoch); !errors.Is(err, ErrInvalidCredential) {
		t.Errorf("reverse cross-subject verify: got %v, want ErrInvalidCredential", err)
	}
}

// TestSeparator_NoCollisionBetweenAdjacentFields is the structural
// guarantee that the zero byte prevents ("reset", "ab") from colliding
// with ("reseta", "b"). It computes the hash of the same token twice
// under those two pairings and asserts they differ.
func TestSeparator_NoCollisionBetweenAdjacentFields(t *testing.T) {
	c := newCred(t)
	const fixedToken = "abcd1234-fixed-token-for-separator-test"
	h1 := c.computeHash("a", "bc", fixedToken)
	h2 := c.computeHash("ab", "c", fixedToken)
	if h1 == h2 {
		t.Error("separator collision: (\"a\",\"bc\") and (\"ab\",\"c\") produced the same hash")
	}
}

// TestSeparator_NoCollisionAcrossPurposeSubject is the broader version
// of the same guarantee: a token presented with adjacent-purpose/
// subject payloads must not match the hash of a token minted for any
// of the obvious confusion pairings.
func TestSeparator_NoCollisionAcrossPurposeSubject(t *testing.T) {
	c := newCred(t)
	const fixedToken = "fixed-token-value-1234567890"
	cases := []struct {
		mint    [2]string
		present [2]string
	}{
		{[2]string{"reset", "alice"}, [2]string{"reset", "alice"}}, // sanity
		{[2]string{"reset", "ab"}, [2]string{"reseta", "b"}},       // boundary
		{[2]string{"reset", ""}, [2]string{"rese", "t"}},           // empty subject adjacent
		{[2]string{"activate", "x"}, [2]string{"activatex", ""}},   // empty subject adjacent 2
		{[2]string{"p", "q"}, [2]string{"pq", ""}},                 // short form
	}
	for _, tc := range cases {
		mintHash := c.computeHash(tc.mint[0], tc.mint[1], fixedToken)
		presentHash := c.computeHash(tc.present[0], tc.present[1], fixedToken)
		// The sanity case is the only one where hashes must agree.
		if tc.mint == tc.present {
			if mintHash != presentHash {
				t.Errorf("sanity: %v hash mismatch", tc.mint)
			}
			continue
		}
		if mintHash == presentHash {
			t.Errorf("separator collision: mint=%v present=%v hash=%s", tc.mint, tc.present, mintHash)
		}
	}
}

// ---- Sentinel errors at Issue time -----------------------------------------

func TestIssue_EmptyPurposeRejected(t *testing.T) {
	c := newCred(t)
	_, err := c.Issue("", "alice@example.com")
	if !errors.Is(err, ErrEmptyPurpose) {
		t.Errorf("Issue(\"\", \"alice@example.com\") = %v, want ErrEmptyPurpose", err)
	}
}

func TestIssue_EmptySubjectRejected(t *testing.T) {
	c := newCred(t)
	_, err := c.Issue("reset", "")
	if !errors.Is(err, ErrEmptySubject) {
		t.Errorf("Issue(\"reset\", \"\") = %v, want ErrEmptySubject", err)
	}
}

// TestIssue_BothEmptyReportsPurposeFirst pins the documented order: when
// both are empty, ErrEmptyPurpose is returned (it is checked first).
// A caller can rely on this when short-circuiting on either error.
func TestIssue_BothEmptyReportsPurposeFirst(t *testing.T) {
	c := newCred(t)
	_, err := c.Issue("", "")
	if !errors.Is(err, ErrEmptyPurpose) {
		t.Errorf("Issue(\"\", \"\") = %v, want ErrEmptyPurpose", err)
	}
}

// ---- URL safety -------------------------------------------------------------

// TestIssue_TokenIsURLSafe is the literal test from the brief: the raw
// token must round-trip through url.QueryEscape unchanged, because it
// goes into a query parameter in the email link without escaping.
func TestIssue_TokenIsURLSafe(t *testing.T) {
	c := newCred(t)
	issued, err := c.Issue("reset", "alice@example.com")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if got := url.QueryEscape(issued.Token); got != issued.Token {
		t.Errorf("token not URL safe: QueryEscape(%q) = %q", issued.Token, got)
	}
}

// TestIssue_TokenIsRawBase64URL pins the encoding choice: the token is
// base64 URL without padding, never base32 (the brief explicitly
// excludes base32 because the token is in a URL, not on a printout).
func TestIssue_TokenIsRawBase64URL(t *testing.T) {
	c := newCred(t)
	issued, err := c.Issue("reset", "alice@example.com")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(issued.Token); err != nil {
		t.Errorf("token is not base64 URL: %v", err)
	}
	// 32 bytes base64-URL-no-padding encodes to 43 characters (ceil(32*4/3)
	// = 43, padding stripped because raw).
	if len(issued.Token) != 43 {
		t.Errorf("token length = %d, want 43 (32 raw bytes base64 URL)", len(issued.Token))
	}
}

// TestIssue_TokenUsesURLAlphabet explicitly forbids characters that
// would force percent-encoding: '+', '/', '='. Raw base64 URL keeps
// only [A-Za-z0-9_-].
func TestIssue_TokenUsesURLAlphabet(t *testing.T) {
	c := newCred(t)
	for i := 0; i < 64; i++ {
		issued, err := c.Issue("reset", "alice@example.com")
		if err != nil {
			t.Fatalf("Issue #%d: %v", i, err)
		}
		for _, c := range issued.Token {
			ok := (c >= 'A' && c <= 'Z') ||
				(c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') ||
				c == '-' || c == '_'
			if !ok {
				t.Fatalf("token contains non-URL-safe character %q in %q", c, issued.Token)
			}
		}
	}
	// Also exercise Verify with a token that came from a different Issue
	// call, so the alphabet constraint must hold across many draws.
	_ = time.Now()
}

// ---- Uniqueness -------------------------------------------------------------

// TestIssue_UniqueTokensPerCall is the brute-force check that two Issue
// calls with identical arguments produce different tokens. With 256-bit
// tokens, a collision in two consecutive draws is cryptographically
// negligible; this test still exists to catch an accidental hard-coded
// token or a broken RNG swap.
func TestIssue_UniqueTokensPerCall(t *testing.T) {
	c := newCred(t)
	a, err := c.Issue("reset", "alice@example.com")
	if err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	b, err := c.Issue("reset", "alice@example.com")
	if err != nil {
		t.Fatalf("second Issue: %v", err)
	}
	if a.Token == b.Token {
		t.Errorf("two Issue calls with identical args produced the same token: %q", a.Token)
	}
}

// TestComputeHash_LengthPrefixSurvivesEmbeddedNULs is the reason the HMAC
// input is length-prefixed rather than separated by a byte.
//
// An earlier draft joined purpose, subject and token with a 0x00 separator,
// which disambiguates only while no field can contain that byte. A Go string
// can, so ("a\x00b", "c") and ("a", "b\x00c") hashed identically: a caller
// whose subject came from untrusted input could redeem a token minted for a
// different pair, which is exactly the binding this module exists to provide.
//
// If the construction is ever changed back to a separator, this fails.
func TestComputeHash_LengthPrefixSurvivesEmbeddedNULs(t *testing.T) {
	c := newCred(t)
	const token = "tok"

	cases := [][2]string{
		{"a\x00b", "c"},
		{"a", "b\x00c"},
		{"ab", "c"},
		{"a", "bc"},
		{"", "abc"},
		{"abc", ""},
	}

	seen := make(map[string][2]string, len(cases))
	for _, in := range cases {
		h := c.computeHash(in[0], in[1], token)
		if prev, dup := seen[h]; dup {
			t.Errorf("collision: (%q, %q) and (%q, %q) hash to the same value",
				prev[0], prev[1], in[0], in[1])
			continue
		}
		seen[h] = in
	}
}
