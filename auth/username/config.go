package username

// minLength and maxLength are fixed by the library.
// They are not configurable — this is a deliberate security standard,
// not an oversight. A username shorter than 3 characters is ambiguous;
// longer than 32 is impractical and increases attack surface on user-facing forms.
const (
	minLength = 3
	maxLength = 32
)

// Config holds the username module configuration.
//
// Length limits (3–32) are fixed by the library and cannot be changed.
// The only application-specific option is ExtraReserved — names that are
// specific to your product and should not be allowed as usernames:
//
//	userMod, err := username.New(auth, username.Config{
//	    ExtraReserved: []string{"yourappname", "yourcompany"},
//	})
type Config struct {
	// ExtraReserved extends the built-in reserved names list with your own
	// application-specific names. Values are lowercased automatically.
	//
	// The built-in list already covers common names like "admin", "root",
	// "api", "system", "null", "bot", etc. Use ExtraReserved to add names
	// specific to your product (e.g. your brand name, feature names).
	ExtraReserved []string
}

// defaultReservedNames is the built-in set of names that cannot be registered.
// These cover infrastructure roles, common attack targets, and names that would
// confuse users into believing they are interacting with the service itself.
var defaultReservedNames = []string{
	// Infrastructure and system accounts
	"admin", "administrator", "root", "superuser", "system",
	// API and service identifiers
	"api", "auth", "oauth", "webhook", "service", "daemon", "bot",
	// Protocol and server names
	"www", "ftp", "smtp", "pop", "imap", "mail", "email",
	// Common anonymous / placeholder identities
	"anonymous", "guest", "user", "me", "self",
	// UI / navigation routes that would clash with URL paths
	"login", "logout", "register", "signup", "signin", "signout",
	"settings", "profile", "account", "dashboard", "home",
	// Special values that could cause parsing ambiguity
	"null", "undefined", "none", "true", "false",
	// Environment and support names
	"test", "dev", "prod", "staging", "support", "help", "info",
}
