package passkey

import (
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/meigma/authkit"
)

// Config describes the WebAuthn relying party that issues passkey challenges.
type Config struct {
	// RPID is the relying-party identifier, usually the effective domain.
	RPID string

	// RPDisplayName is the human-readable relying-party name shown by authenticators.
	RPDisplayName string

	// RPOrigins are accepted browser origins for passkey responses.
	RPOrigins []string

	// RegistrationTimeout overrides the server-enforced registration ceremony timeout.
	// Zero selects the package default.
	RegistrationTimeout time.Duration

	// LoginTimeout overrides the server-enforced login ceremony timeout.
	// Zero selects the package default.
	LoginTimeout time.Duration
}

// User describes an authkit principal's WebAuthn user account for one relying party.
type User struct {
	// RPID identifies the relying party this passkey user belongs to.
	RPID string

	// PrincipalID identifies the authkit principal represented by this passkey user.
	PrincipalID string

	// Handle is the opaque WebAuthn user handle for this principal and relying party.
	Handle []byte

	// Name is the human-palatable WebAuthn account name.
	Name string

	// DisplayName is the display name shown during passkey registration.
	DisplayName string
}

// Credential describes a stored WebAuthn passkey credential.
type Credential struct {
	// RPID identifies the relying party this credential belongs to.
	RPID string

	// PrincipalID identifies the authkit principal that owns the credential.
	PrincipalID string

	// UserHandle is the opaque WebAuthn user handle that owns the credential.
	UserHandle []byte

	// CredentialID is the WebAuthn credential identifier.
	CredentialID []byte

	// WebAuthn contains the upstream credential record that must be preserved for verification.
	WebAuthn webauthn.Credential
}

// Registration is the atomic storage unit for a completed passkey registration.
type Registration struct {
	// User is the WebAuthn user handle that owns Credential.
	User User

	// Credential is the verified passkey credential to persist.
	Credential Credential

	// Identity is the passkey identity to link to User.PrincipalID.
	Identity authkit.Identity
}

// RegistrationResult describes an atomically persisted passkey registration.
type RegistrationResult struct {
	// User is the persisted WebAuthn user handle.
	User User

	// Credential is the persisted passkey credential.
	Credential Credential

	// Link is the canonical authkit external identity link for Identity.
	Link authkit.ExternalIdentity
}

// BeginRegistrationRequest describes a passkey registration ceremony start.
type BeginRegistrationRequest struct {
	// PrincipalID identifies the authkit principal receiving the passkey.
	PrincipalID string

	// Name is the human-palatable WebAuthn account name.
	Name string

	// DisplayName is the display name shown during passkey registration.
	DisplayName string
}

// BeginRegistrationResult contains browser options and server-side session data for registration.
type BeginRegistrationResult struct {
	// Creation is the WebAuthn credential creation payload to send to the browser.
	Creation *protocol.CredentialCreation

	// SessionData must be securely stored by the consumer until FinishRegistration.
	SessionData webauthn.SessionData

	// User is the passkey user used for the ceremony and must be stored with SessionData.
	User User
}

// FinishRegistrationRequest describes a passkey registration ceremony finish.
type FinishRegistrationRequest struct {
	// PrincipalID identifies the authkit principal receiving the passkey.
	PrincipalID string

	// User is the exact passkey user returned by BeginRegistration.
	User User

	// SessionData is the exact session data returned by BeginRegistration.
	SessionData webauthn.SessionData

	// Response is the raw WebAuthn registration response JSON from the browser.
	Response []byte
}

// FinishRegistrationResult contains the stored credential and verified identity.
type FinishRegistrationResult struct {
	// Identity is the verified passkey identity for onboarding or attachment.
	Identity authkit.Identity

	// Link is the canonical authkit external identity link for Identity.
	Link authkit.ExternalIdentity

	// Credential is the credential stored for future passkey logins.
	Credential Credential
}

// BeginLoginRequest describes a discoverable passkey login ceremony start.
type BeginLoginRequest struct{}

// BeginLoginResult contains browser options and server-side session data for login.
type BeginLoginResult struct {
	// Assertion is the WebAuthn credential assertion payload to send to the browser.
	Assertion *protocol.CredentialAssertion

	// SessionData must be securely stored by the consumer until FinishLogin.
	SessionData webauthn.SessionData
}

// FinishLoginRequest describes a discoverable passkey login ceremony finish.
type FinishLoginRequest struct {
	// SessionData is the exact session data returned by BeginLogin.
	SessionData webauthn.SessionData

	// Response is the raw WebAuthn assertion response JSON from the browser.
	Response []byte
}

// FinishLoginResult contains the verified credential owner and identity.
type FinishLoginResult struct {
	// Identity is the verified passkey identity for authkit exchange.
	Identity authkit.Identity

	// User is the passkey user authenticated by the ceremony.
	User User

	// Credential is the credential updated after successful login validation.
	Credential Credential
}
