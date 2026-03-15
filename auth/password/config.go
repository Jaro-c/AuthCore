package password

import "fmt"

// Config holds the password module configuration.
//
// Only the Argon2id work parameters are tunable — Memory, Iterations, and
// Parallelism. The algorithm (Argon2id), salt size (16 bytes), and key size
// (32 bytes) are fixed to enforce consistent security across all deployments.
//
// Start from DefaultConfig and override only what your hardware supports:
//
//	cfg := password.DefaultConfig()
//	cfg.Memory      = 128 * 1024  // 128 MiB — for a dedicated auth server
//	cfg.Iterations  = 4
//	cfg.Parallelism = 4           // match your guaranteed CPU core count
//	pwdMod, err := password.New(auth, cfg)
type Config struct {
	// Memory is the amount of memory used by Argon2id, in kibibytes.
	// Higher values increase resistance to GPU/ASIC brute-force attacks.
	// Defaults to 65536 (64 MiB). Minimum 8192 (8 MiB).
	Memory uint32

	// Iterations is the number of passes Argon2id makes over the memory.
	// Higher values increase the CPU cost per hash without changing memory use.
	// Defaults to 3. Minimum 1.
	Iterations uint32

	// Parallelism is the number of threads Argon2id uses.
	// Set this to the minimum number of CPU cores guaranteed to your service.
	// Defaults to 2. Minimum 1.
	Parallelism uint8

	// DisablePolicy disables the built-in password policy check inside Hash.
	//
	// By default, Hash rejects any password that does not satisfy all of:
	//   - Between 12 and 64 characters
	//   - At least one uppercase letter
	//   - At least one lowercase letter
	//   - At least one digit
	//   - At least one special character (anything that is not a letter or digit)
	//
	// Set DisablePolicy to true only when you apply your own validation before
	// calling Hash, or when migrating legacy password hashes.
	DisablePolicy bool
}

// DefaultConfig returns a Config with OWASP-recommended Argon2id defaults.
//
// The defaults are calibrated for a server with at least 2 vCPUs and 4 GiB of
// RAM. Each Hash call temporarily allocates Memory kibibytes (64 MiB) of RAM.
// Tune Memory and Iterations upward on more capable hardware to strengthen the
// work factor over time.
func DefaultConfig() Config {
	return Config{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
	}
}

// applyDefaults fills zero-value fields with values from DefaultConfig.
func applyDefaults(cfg Config) Config {
	def := DefaultConfig()
	if cfg.Memory == 0 {
		cfg.Memory = def.Memory
	}
	if cfg.Iterations == 0 {
		cfg.Iterations = def.Iterations
	}
	if cfg.Parallelism == 0 {
		cfg.Parallelism = def.Parallelism
	}
	return cfg
}

// validateConfig returns an error if cfg contains invalid values.
// applyDefaults is always called before validateConfig, so Iterations and
// Parallelism are guaranteed to be ≥ 1 by the time this runs.
func validateConfig(cfg Config) error {
	if cfg.Memory < 8*1024 {
		return fmt.Errorf("memory must be at least 8192 KiB (8 MiB), got %d", cfg.Memory)
	}
	return nil
}
