package passkey

import (
	"maps"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/meigma/authkit"
)

func cloneConfig(config Config) Config {
	return Config{
		RPID:                config.RPID,
		RPDisplayName:       config.RPDisplayName,
		RPOrigins:           cloneStrings(config.RPOrigins),
		RegistrationTimeout: config.RegistrationTimeout,
		LoginTimeout:        config.LoginTimeout,
	}
}

func cloneUser(user User) User {
	return User{
		RPID:        user.RPID,
		PrincipalID: user.PrincipalID,
		Handle:      cloneBytes(user.Handle),
		Name:        user.Name,
		DisplayName: user.DisplayName,
	}
}

func cloneCredential(credential Credential) Credential {
	return Credential{
		RPID:         credential.RPID,
		PrincipalID:  credential.PrincipalID,
		UserHandle:   cloneBytes(credential.UserHandle),
		CredentialID: cloneBytes(credential.CredentialID),
		WebAuthn:     cloneWebAuthnCredential(credential.WebAuthn),
	}
}

func cloneRegistration(registration Registration) Registration {
	return Registration{
		User:       cloneUser(registration.User),
		Credential: cloneCredential(registration.Credential),
		Identity:   cloneIdentity(registration.Identity),
	}
}

func cloneCredentials(credentials []Credential) []Credential {
	if len(credentials) == 0 {
		return nil
	}
	clones := make([]Credential, 0, len(credentials))
	for _, credential := range credentials {
		clones = append(clones, cloneCredential(credential))
	}

	return clones
}

func cloneWebAuthnCredential(credential webauthn.Credential) webauthn.Credential {
	clone := credential
	clone.ID = cloneBytes(credential.ID)
	clone.PublicKey = cloneBytes(credential.PublicKey)
	clone.Transport = append(clone.Transport[:0:0], credential.Transport...)
	clone.Authenticator.AAGUID = cloneBytes(credential.Authenticator.AAGUID)
	clone.Attestation.ClientDataJSON = cloneBytes(credential.Attestation.ClientDataJSON)
	clone.Attestation.ClientDataHash = cloneBytes(credential.Attestation.ClientDataHash)
	clone.Attestation.AuthenticatorData = cloneBytes(credential.Attestation.AuthenticatorData)
	clone.Attestation.Object = cloneBytes(credential.Attestation.Object)

	return clone
}

func cloneIdentity(identity authkit.Identity) authkit.Identity {
	clone := identity
	if identity.Claims != nil {
		clone.Claims = make(map[string]any, len(identity.Claims))
		maps.Copy(clone.Claims, identity.Claims)
	}

	return clone
}

func cloneBytes(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}

	clone := make([]byte, len(value))
	copy(clone, value)
	return clone
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	clone := make([]string, len(values))
	copy(clone, values)
	return clone
}
