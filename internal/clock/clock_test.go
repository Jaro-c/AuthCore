package clock_test

import (
	"testing"
	"time"

	"github.com/Jaro-c/authcore/internal/clock"
)

func TestNew_defaultsToUTC(t *testing.T) {
	clk := clock.New(nil)
	now := clk.Now()

	if now.Location() != time.UTC {
		t.Errorf("expected UTC, got %s", now.Location())
	}
}

func TestNew_honoursLocation(t *testing.T) {
	bogota, err := time.LoadLocation("America/Bogota")
	if err != nil {
		t.Fatalf("failed to load location: %v", err)
	}

	clk := clock.New(bogota)
	now := clk.Now()

	if now.Location().String() != bogota.String() {
		t.Errorf("expected %s, got %s", bogota, now.Location())
	}
}

func TestNew_nowIsRecent(t *testing.T) {
	clk := clock.New(time.UTC)
	before := time.Now().UTC()
	got := clk.Now()
	after := time.Now().UTC()

	if got.Before(before) || got.After(after) {
		t.Errorf("Now() = %v, want value between %v and %v", got, before, after)
	}
}

// FixedClock is an example of a test double that callers of internal/clock
// can use in their own unit tests to control time.
type FixedClock struct{ t time.Time }

func (f FixedClock) Now() time.Time { return f.t }

func TestFixedClock_implementsClock(t *testing.T) {
	fixed := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
	var clk clock.Clock = FixedClock{t: fixed}

	if !clk.Now().Equal(fixed) {
		t.Errorf("expected %v, got %v", fixed, clk.Now())
	}
}
