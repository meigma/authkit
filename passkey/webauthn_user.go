package passkey

import (
	"bytes"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
)

type webAuthnUser struct {
	user        User
	credentials []Credential
}

func newWebAuthnUser(user User, credentials []Credential) (webAuthnUser, error) {
	validCredentials, err := credentialsForUser(user, credentials)
	if err != nil {
		return webAuthnUser{}, err
	}

	return webAuthnUser{
		user:        cloneUser(user),
		credentials: validCredentials,
	}, nil
}

func (u webAuthnUser) WebAuthnID() []byte {
	return cloneBytes(u.user.Handle)
}

func (u webAuthnUser) WebAuthnName() string {
	return u.user.Name
}

func (u webAuthnUser) WebAuthnDisplayName() string {
	return u.user.DisplayName
}

func (u webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	credentials := make([]webauthn.Credential, 0, len(u.credentials))
	for _, credential := range u.credentials {
		upstream := cloneWebAuthnCredential(credential.WebAuthn)
		if len(upstream.ID) == 0 {
			upstream.ID = cloneBytes(credential.CredentialID)
		}
		credentials = append(credentials, upstream)
	}

	return credentials
}

func credentialsForUser(user User, credentials []Credential) ([]Credential, error) {
	if len(credentials) == 0 {
		return nil, nil
	}

	valid := make([]Credential, 0, len(credentials))
	for _, credential := range credentials {
		if credential.RPID != user.RPID {
			return nil, fmt.Errorf(
				"credential relying party %q does not match user relying party %q",
				credential.RPID,
				user.RPID,
			)
		}
		if credential.PrincipalID != user.PrincipalID {
			return nil, fmt.Errorf(
				"credential principal %q does not match user principal %q",
				credential.PrincipalID,
				user.PrincipalID,
			)
		}
		if !bytes.Equal(credential.UserHandle, user.Handle) {
			return nil, errorsForCredentialUserHandle(credential)
		}
		if len(credential.CredentialID) == 0 {
			return nil, errorsForCredentialID("credential ID is required")
		}
		if len(credential.WebAuthn.ID) > 0 && !bytes.Equal(credential.WebAuthn.ID, credential.CredentialID) {
			return nil, errorsForCredentialID("credential WebAuthn ID does not match credential ID")
		}

		cloned := cloneCredential(credential)
		if len(cloned.WebAuthn.ID) == 0 {
			cloned.WebAuthn.ID = cloneBytes(cloned.CredentialID)
		}
		valid = append(valid, cloned)
	}

	return valid, nil
}

func credentialByID(credentials []Credential, credentialID []byte) (Credential, bool) {
	for _, credential := range credentials {
		if bytes.Equal(credential.CredentialID, credentialID) {
			return cloneCredential(credential), true
		}
	}

	return Credential{}, false
}

func errorsForCredentialUserHandle(credential Credential) error {
	return fmt.Errorf(
		"credential %q user handle does not match passkey user",
		credentialIDString(credential.CredentialID),
	)
}

func errorsForCredentialID(reason string) error {
	return fmt.Errorf("credential invalid: %s", reason)
}
