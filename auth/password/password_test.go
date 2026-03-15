package password

import (
	"errors"
	"strings"
	"testing"

	"github.com/Jaro-c/authcore"
)

// ---- test infrastructure ----------------------------------------------------

// fakeProvider satisfies authcore.Provider with a silent logger and no keys.
type fakeProvider struct{}

func (fakeProvider) Config() authcore.Config { return authcore.DefaultConfig() }
func (fakeProvider) Logger() authcore.Logger { return silentLogger{} }
func (fakeProvider) Keys() authcore.Keys     { return nil }

type silentLogger struct{}

func (silentLogger) Debug(string, ...any) {}
func (silentLogger) Info(string, ...any)  {}
func (silentLogger) Warn(string, ...any)  {}
func (silentLogger) Error(string, ...any) {}

func newMod(t *testing.T) *Password {
	t.Helper()
	mod, err := New(fakeProvider{}, DefaultConfig())
	if err != nil {
		t.Fatalf("New(DefaultConfig) error = %v", err)
	}
	return mod
}

// ---- New() ------------------------------------------------------------------

func TestNew_defaultConfigSucceeds(t *testing.T) {
	_, err := New(fakeProvider{}, DefaultConfig())
	if err != nil {
		t.Fatalf("New(DefaultConfig) error = %v", err)
	}
}

func TestNew_zeroConfigSucceedsBecauseDefaultsAreApplied(t *testing.T) {
	_, err := New(fakeProvider{}, Config{})
	if err != nil {
		t.Fatalf("New(Config{}) error = %v; applyDefaults should have filled zero values", err)
	}
}

func TestNew_tooLowMemoryReturnsErrInvalidConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Memory = 1024 // below 8 MiB minimum

	_, err := New(fakeProvider{}, cfg)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNew_zeroIterationsAreFilledByDefaults(t *testing.T) {
	cfg := Config{Memory: DefaultConfig().Memory, Parallelism: 2}
	// Iterations == 0 → applyDefaults fills it → no error
	_, err := New(fakeProvider{}, cfg)
	if err != nil {
		t.Fatalf("expected nil error when Iterations=0, got %v", err)
	}
}

func TestNew_zeroParallelismIsFilledByDefaults(t *testing.T) {
	cfg := Config{Memory: DefaultConfig().Memory, Iterations: 1}
	// Parallelism == 0 → applyDefaults fills it → no error
	_, err := New(fakeProvider{}, cfg)
	if err != nil {
		t.Fatalf("expected nil error when Parallelism=0, got %v", err)
	}
}

// ---- Name() -----------------------------------------------------------------

func TestName(t *testing.T) {
	mod := newMod(t)
	if mod.Name() != "password" {
		t.Errorf("Name() = %q, want %q", mod.Name(), "password")
	}
}

// ---- Hash() -----------------------------------------------------------------

func TestHash_returnsPHCFormat(t *testing.T) {
	mod := newMod(t)
	hash, err := mod.Hash("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=") {
		t.Errorf("Hash() = %q, expected PHC prefix $argon2id$v=", hash)
	}
}

func TestHash_saltIsRandom(t *testing.T) {
	mod := newMod(t)
	h1, err := mod.Hash("same-password")
	if err != nil {
		t.Fatalf("Hash() first call error = %v", err)
	}
	h2, err := mod.Hash("same-password")
	if err != nil {
		t.Fatalf("Hash() second call error = %v", err)
	}
	if h1 == h2 {
		t.Error("two Hash() calls with the same password produced identical output — salt is not random")
	}
}

func TestHash_embedsConfigParams(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Memory = 16 * 1024
	cfg.Iterations = 2
	cfg.Parallelism = 1

	mod, err := New(fakeProvider{}, cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	hash, err := mod.Hash("password")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	if !strings.Contains(hash, "m=16384,t=2,p=1") {
		t.Errorf("Hash() = %q, expected to contain m=16384,t=2,p=1", hash)
	}
}

// ---- Verify() ---------------------------------------------------------------

func TestVerify_correctPassword(t *testing.T) {
	mod := newMod(t)
	hash, err := mod.Hash("my-secret-password")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	ok, err := mod.Verify("my-secret-password", hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !ok {
		t.Error("Verify() = false for the correct password, want true")
	}
}

func TestVerify_wrongPassword(t *testing.T) {
	mod := newMod(t)
	hash, err := mod.Hash("my-secret-password")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	ok, err := mod.Verify("wrong-password", hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if ok {
		t.Error("Verify() = true for a wrong password, want false")
	}
}

func TestVerify_emptyPasswordDoesNotMatch(t *testing.T) {
	mod := newMod(t)
	hash, err := mod.Hash("not-empty")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	ok, err := mod.Verify("", hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if ok {
		t.Error("Verify() = true for empty password, want false")
	}
}

func TestVerify_malformedHashReturnsErrInvalidHash(t *testing.T) {
	mod := newMod(t)

	_, err := mod.Verify("password", "not-a-phc-string")
	if !errors.Is(err, ErrInvalidHash) {
		t.Errorf("expected ErrInvalidHash, got %v", err)
	}
}

func TestVerify_wrongAlgorithmReturnsErrInvalidHash(t *testing.T) {
	mod := newMod(t)
	wrongAlg := "$bcrypt$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$c29tZWtleQ"

	_, err := mod.Verify("password", wrongAlg)
	if !errors.Is(err, ErrInvalidHash) {
		t.Errorf("expected ErrInvalidHash, got %v", err)
	}
}

func TestVerify_usesParamsFromStoredHash(t *testing.T) {
	// Hash with low-cost config (fast for tests).
	lowCost := Config{Memory: 8 * 1024, Iterations: 1, Parallelism: 1}
	hashMod, err := New(fakeProvider{}, lowCost)
	if err != nil {
		t.Fatalf("New(lowCost) error = %v", err)
	}

	hash, err := hashMod.Hash("password")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	// Verify with a different module config — must still succeed because Verify
	// reads the parameters from the stored hash, not from the module's Config.
	verifyMod := newMod(t) // uses DefaultConfig (64 MiB / 3 iterations)
	ok, err := verifyMod.Verify("password", hash)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !ok {
		t.Error("Verify() = false; stored hash should be verifiable even when module config differs")
	}
}

// ---- DefaultConfig() --------------------------------------------------------

func TestDefaultConfig_values(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Memory != 64*1024 {
		t.Errorf("DefaultConfig().Memory = %d, want %d", cfg.Memory, 64*1024)
	}
	if cfg.Iterations != 3 {
		t.Errorf("DefaultConfig().Iterations = %d, want 3", cfg.Iterations)
	}
	if cfg.Parallelism != 2 {
		t.Errorf("DefaultConfig().Parallelism = %d, want 2", cfg.Parallelism)
	}
}

// ---- applyDefaults() --------------------------------------------------------

func TestApplyDefaults_fillsZeroMemory(t *testing.T) {
	cfg := applyDefaults(Config{Iterations: 1, Parallelism: 1})
	if cfg.Memory != DefaultConfig().Memory {
		t.Errorf("applyDefaults zero Memory = %d, want %d", cfg.Memory, DefaultConfig().Memory)
	}
}

func TestApplyDefaults_fillsZeroIterations(t *testing.T) {
	cfg := applyDefaults(Config{Memory: 8 * 1024, Parallelism: 1})
	if cfg.Iterations != DefaultConfig().Iterations {
		t.Errorf("applyDefaults zero Iterations = %d, want %d", cfg.Iterations, DefaultConfig().Iterations)
	}
}

func TestApplyDefaults_fillsZeroParallelism(t *testing.T) {
	cfg := applyDefaults(Config{Memory: 8 * 1024, Iterations: 1})
	if cfg.Parallelism != DefaultConfig().Parallelism {
		t.Errorf("applyDefaults zero Parallelism = %d, want %d", cfg.Parallelism, DefaultConfig().Parallelism)
	}
}
