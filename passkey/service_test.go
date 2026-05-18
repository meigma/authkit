package passkey

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
)

const (
	testRPID        = "example.test"
	testPrincipalID = "principal_123"
)

func TestNewServiceValidatesConfig(t *testing.T) {
	validConfig := testConfig()

	tests := []struct {
		name    string
		store   Store
		config  Config
		wantErr string
	}{
		{
			name:    "missing store",
			config:  validConfig,
			wantErr: "store is required",
		},
		{
			name:  "missing RP ID",
			store: newFakeStore(),
			config: Config{
				RPDisplayName: validConfig.RPDisplayName,
				RPOrigins:     validConfig.RPOrigins,
			},
			wantErr: "RP ID is required",
		},
		{
			name:  "missing RP display name",
			store: newFakeStore(),
			config: Config{
				RPID:      validConfig.RPID,
				RPOrigins: validConfig.RPOrigins,
			},
			wantErr: "RP display name is required",
		},
		{
			name:  "missing RP origins",
			store: newFakeStore(),
			config: Config{
				RPID:          validConfig.RPID,
				RPDisplayName: validConfig.RPDisplayName,
			},
			wantErr: "RP origins are required",
		},
		{
			name:  "blank RP origin",
			store: newFakeStore(),
			config: Config{
				RPID:          validConfig.RPID,
				RPDisplayName: validConfig.RPDisplayName,
				RPOrigins:     []string{""},
			},
			wantErr: "RP origin 0 is required",
		},
		{
			name:  "negative registration timeout",
			store: newFakeStore(),
			config: Config{
				RPID:                validConfig.RPID,
				RPDisplayName:       validConfig.RPDisplayName,
				RPOrigins:           validConfig.RPOrigins,
				RegistrationTimeout: -time.Second,
			},
			wantErr: "registration timeout must be positive",
		},
		{
			name:  "negative login timeout",
			store: newFakeStore(),
			config: Config{
				RPID:          validConfig.RPID,
				RPDisplayName: validConfig.RPDisplayName,
				RPOrigins:     validConfig.RPOrigins,
				LoginTimeout:  -time.Second,
			},
			wantErr: "login timeout must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewService(tt.store, tt.config)

			require.ErrorContains(t, err, tt.wantErr)
			assert.Nil(t, service)
		})
	}
}

func TestNewServiceAcceptsValidConfig(t *testing.T) {
	service, err := NewService(newFakeStore(), testConfig())

	require.NoError(t, err)
	assert.NotNil(t, service)
}

func TestNewServiceEnforcesDefaultCeremonyTimeouts(t *testing.T) {
	service, err := NewService(newFakeStore(), testConfig())
	require.NoError(t, err)

	registration, err := service.BeginRegistration(context.Background(), BeginRegistrationRequest{
		PrincipalID: testPrincipalID,
		Name:        "ada@example.test",
		DisplayName: "Ada Lovelace",
	})
	require.NoError(t, err)
	assert.Equal(t, int(defaultRegistrationTimeout.Milliseconds()), registration.Creation.Response.Timeout)
	assert.False(t, registration.SessionData.Expires.IsZero())

	login, err := service.BeginLogin(context.Background(), BeginLoginRequest{})
	require.NoError(t, err)
	assert.Equal(t, int(defaultLoginTimeout.Milliseconds()), login.Assertion.Response.Timeout)
	assert.False(t, login.SessionData.Expires.IsZero())
}

func TestNewServiceAcceptsCustomCeremonyTimeouts(t *testing.T) {
	const (
		registrationTimeout = 2 * time.Minute
		loginTimeout        = 90 * time.Second
	)
	config := testConfig()
	config.RegistrationTimeout = registrationTimeout
	config.LoginTimeout = loginTimeout
	service, err := NewService(newFakeStore(), config)
	require.NoError(t, err)

	registration, err := service.BeginRegistration(context.Background(), BeginRegistrationRequest{
		PrincipalID: testPrincipalID,
		Name:        "ada@example.test",
		DisplayName: "Ada Lovelace",
	})
	require.NoError(t, err)
	assert.Equal(t, int(registrationTimeout.Milliseconds()), registration.Creation.Response.Timeout)
	assert.False(t, registration.SessionData.Expires.IsZero())

	login, err := service.BeginLogin(context.Background(), BeginLoginRequest{})
	require.NoError(t, err)
	assert.Equal(t, int(loginTimeout.Milliseconds()), login.Assertion.Response.Timeout)
	assert.False(t, login.SessionData.Expires.IsZero())
}

func TestBeginRegistrationGeneratesSessionUser(t *testing.T) {
	store := newFakeStore()
	rp := newFakeRelyingParty()
	service := newTestService(t, store, rp)

	result, err := service.BeginRegistration(context.Background(), BeginRegistrationRequest{
		PrincipalID: testPrincipalID,
		Name:        "ada@example.test",
		DisplayName: "Ada Lovelace",
	})

	require.NoError(t, err)
	assert.Same(t, rp.creation, result.Creation)
	assert.Equal(t, *rp.registrationSession, result.SessionData)
	assert.Empty(t, store.usersByPrincipal)
	assert.Empty(t, store.createdRegistrations)
	assert.Equal(t, testRPID, result.User.RPID)
	assert.Equal(t, testPrincipalID, result.User.PrincipalID)
	assert.Len(t, result.User.Handle, userHandleBytes)
	assert.Equal(t, "ada@example.test", result.User.Name)
	assert.Equal(t, "Ada Lovelace", result.User.DisplayName)
	assert.Equal(t, protocol.VerificationRequired, result.SessionData.UserVerification)
	assert.Equal(t, protocol.VerificationRequired, rp.creation.Response.AuthenticatorSelection.UserVerification)
	assert.Equal(t, protocol.ResidentKeyRequirementRequired, rp.creation.Response.AuthenticatorSelection.ResidentKey)
	assert.Equal(t, result.User.Handle, rp.registrationUser.WebAuthnID())
	assert.Empty(t, rp.registrationUser.WebAuthnCredentials())
	assert.Empty(t, result.Creation.Response.CredentialExcludeList)
}

func TestBeginRegistrationReusesPasskeyUserAndCredentials(t *testing.T) {
	store := newFakeStore()
	user := testUser()
	store.putUser(user)
	store.putCredential(Credential{
		RPID:         testRPID,
		PrincipalID:  testPrincipalID,
		UserHandle:   user.Handle,
		CredentialID: []byte("credential-1"),
		WebAuthn: webauthn.Credential{
			ID:        []byte("credential-1"),
			PublicKey: []byte("public-key"),
		},
	})
	rp := newFakeRelyingParty()
	service := newTestService(t, store, rp)

	result, err := service.BeginRegistration(context.Background(), BeginRegistrationRequest{
		PrincipalID: testPrincipalID,
		Name:        "ignored@example.test",
		DisplayName: "Ignored",
	})

	require.NoError(t, err)
	assert.Empty(t, store.createdRegistrations)
	assert.Equal(t, user, result.User)
	credentials := rp.registrationUser.WebAuthnCredentials()
	require.Len(t, credentials, 1)
	assert.Equal(t, []byte("credential-1"), credentials[0].ID)
	assert.Equal(t, []byte("public-key"), credentials[0].PublicKey)
	exclusions := result.Creation.Response.CredentialExcludeList
	require.Len(t, exclusions, 1)
	assert.Equal(t, protocol.PublicKeyCredentialType, exclusions[0].Type)
	assert.Equal(t, []byte("credential-1"), []byte(exclusions[0].CredentialID))
}

func TestFinishRegistrationStoresCredentialAndReturnsIdentity(t *testing.T) {
	store := newFakeStore()
	user := testUser()
	store.putUser(user)
	rp := newFakeRelyingParty()
	rp.createdCredential = &webauthn.Credential{
		ID:        []byte("credential-1"),
		PublicKey: []byte("public-key"),
		Authenticator: webauthn.Authenticator{
			SignCount: 2,
		},
	}
	service := newTestService(t, store, rp)
	response := []byte(`{"id":"credential-1"}`)
	identity := identityForCredential(testRPID, user.Handle, rp.createdCredential.ID)
	service.parseCreationResponse = func(data []byte) (*protocol.ParsedCredentialCreationData, error) {
		assert.Equal(t, response, data)
		return &protocol.ParsedCredentialCreationData{}, nil
	}

	result, err := service.FinishRegistration(context.Background(), FinishRegistrationRequest{
		PrincipalID: testPrincipalID,
		User:        user,
		SessionData: webauthn.SessionData{Challenge: "registration-challenge"},
		Response:    response,
	})

	require.NoError(t, err)
	assert.Equal(t, []string{"createRegistration"}, store.calls)
	require.Len(t, store.createdRegistrations, 1)
	createdRegistration := store.createdRegistrations[0]
	assert.Equal(t, user, createdRegistration.User)
	assert.Equal(t, identity, createdRegistration.Identity)
	createdCredential := createdRegistration.Credential
	assert.Equal(t, testRPID, createdCredential.RPID)
	assert.Equal(t, testPrincipalID, createdCredential.PrincipalID)
	assert.Equal(t, user.Handle, createdCredential.UserHandle)
	assert.Equal(t, []byte("credential-1"), createdCredential.CredentialID)
	assert.Equal(t, []byte("public-key"), createdCredential.WebAuthn.PublicKey)
	assert.Equal(t, uint32(2), createdCredential.WebAuthn.Authenticator.SignCount)
	assert.Equal(t, createdCredential, result.Credential)
	assert.Equal(t, identity, result.Identity)
	assert.Equal(t, authkit.ExternalIdentity{
		Provider:    identity.Provider,
		Subject:     identity.Subject,
		PrincipalID: testPrincipalID,
	}, result.Link)
	assert.Equal(t, user.Handle, rp.createCredentialUser.WebAuthnID())
	assert.Equal(t, webauthn.SessionData{
		Challenge:        "registration-challenge",
		UserVerification: protocol.VerificationRequired,
	}, rp.createCredentialSession)
}

func TestFinishRegistrationRejectsMismatchedRegistrationResult(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(RegistrationResult) RegistrationResult
	}{
		{
			name: "user RP ID",
			mutate: func(result RegistrationResult) RegistrationResult {
				result.User.RPID = "other.example.test"
				return result
			},
		},
		{
			name: "user principal",
			mutate: func(result RegistrationResult) RegistrationResult {
				result.User.PrincipalID = "other-principal"
				return result
			},
		},
		{
			name: "user handle",
			mutate: func(result RegistrationResult) RegistrationResult {
				result.User.Handle = []byte("other-handle")
				return result
			},
		},
		{
			name: "credential RP ID",
			mutate: func(result RegistrationResult) RegistrationResult {
				result.Credential.RPID = "other.example.test"
				return result
			},
		},
		{
			name: "credential principal",
			mutate: func(result RegistrationResult) RegistrationResult {
				result.Credential.PrincipalID = "other-principal"
				return result
			},
		},
		{
			name: "credential user handle",
			mutate: func(result RegistrationResult) RegistrationResult {
				result.Credential.UserHandle = []byte("other-handle")
				return result
			},
		},
		{
			name: "credential ID",
			mutate: func(result RegistrationResult) RegistrationResult {
				result.Credential.CredentialID = []byte("other-credential")
				return result
			},
		},
		{
			name: "credential WebAuthn ID",
			mutate: func(result RegistrationResult) RegistrationResult {
				result.Credential.WebAuthn.ID = []byte("other-credential")
				return result
			},
		},
		{
			name: "link provider",
			mutate: func(result RegistrationResult) RegistrationResult {
				result.Link.Provider = "passkey:other.example.test"
				return result
			},
		},
		{
			name: "link subject",
			mutate: func(result RegistrationResult) RegistrationResult {
				result.Link.Subject = "other-subject"
				return result
			},
		},
		{
			name: "link principal",
			mutate: func(result RegistrationResult) RegistrationResult {
				result.Link.PrincipalID = "other-principal"
				return result
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newFakeStore()
			user := testUser()
			store.putUser(user)
			store.createRegistrationResult = tt.mutate
			rp := newFakeRelyingParty()
			rp.createdCredential = &webauthn.Credential{
				ID:        []byte("credential-1"),
				PublicKey: []byte("public-key"),
			}
			service := newTestService(t, store, rp)
			service.parseCreationResponse = func([]byte) (*protocol.ParsedCredentialCreationData, error) {
				return &protocol.ParsedCredentialCreationData{}, nil
			}

			result, err := service.FinishRegistration(context.Background(), FinishRegistrationRequest{
				PrincipalID: testPrincipalID,
				User:        user,
				SessionData: webauthn.SessionData{Challenge: "registration-challenge"},
				Response:    []byte(`{"id":"credential-1"}`),
			})

			require.ErrorIs(t, err, authkit.ErrInternal)
			assert.Empty(t, result)
		})
	}
}

func TestFinishRegistrationOverridesDowngradedUserVerification(t *testing.T) {
	store := newFakeStore()
	user := testUser()
	store.putUser(user)
	rp := newFakeRelyingParty()
	rp.createdCredential = &webauthn.Credential{ID: []byte("credential-1")}
	service := newTestService(t, store, rp)
	service.parseCreationResponse = func([]byte) (*protocol.ParsedCredentialCreationData, error) {
		return &protocol.ParsedCredentialCreationData{}, nil
	}

	result, err := service.FinishRegistration(context.Background(), FinishRegistrationRequest{
		PrincipalID: testPrincipalID,
		User:        user,
		SessionData: webauthn.SessionData{
			Challenge:        "registration-challenge",
			UserVerification: protocol.VerificationDiscouraged,
		},
		Response: []byte(`{"id":"credential-1"}`),
	})

	require.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Equal(t, protocol.VerificationRequired, rp.createCredentialSession.UserVerification)
}

func TestFinishRegistrationReturnsDuplicateCredential(t *testing.T) {
	store := newFakeStore()
	store.putUser(testUser())
	store.createRegistrationErr = ErrCredentialExists
	rp := newFakeRelyingParty()
	rp.createdCredential = &webauthn.Credential{ID: []byte("credential-1")}
	service := newTestService(t, store, rp)
	service.parseCreationResponse = func([]byte) (*protocol.ParsedCredentialCreationData, error) {
		return &protocol.ParsedCredentialCreationData{}, nil
	}

	result, err := service.FinishRegistration(context.Background(), FinishRegistrationRequest{
		PrincipalID: testPrincipalID,
		User:        testUser(),
		SessionData: webauthn.SessionData{Challenge: "registration-challenge"},
		Response:    []byte(`{"id":"credential-1"}`),
	})

	require.ErrorIs(t, err, ErrCredentialExists)
	require.NotErrorIs(t, err, authkit.ErrInternal)
	assert.Empty(t, result)
}

func TestFinishRegistrationReturnsDuplicateUser(t *testing.T) {
	store := newFakeStore()
	store.createRegistrationErr = ErrUserExists
	user := testUser()
	rp := newFakeRelyingParty()
	rp.createdCredential = &webauthn.Credential{ID: []byte("credential-1")}
	service := newTestService(t, store, rp)
	service.parseCreationResponse = func([]byte) (*protocol.ParsedCredentialCreationData, error) {
		return &protocol.ParsedCredentialCreationData{}, nil
	}

	result, err := service.FinishRegistration(context.Background(), FinishRegistrationRequest{
		PrincipalID: testPrincipalID,
		User:        user,
		SessionData: webauthn.SessionData{Challenge: "registration-challenge"},
		Response:    []byte(`{"id":"credential-1"}`),
	})

	require.ErrorIs(t, err, ErrUserExists)
	require.NotErrorIs(t, err, authkit.ErrInternal)
	assert.Empty(t, result)
}

func TestFinishRegistrationWrapsStoreFailures(t *testing.T) {
	storeErr := errors.New("store failed")
	store := newFakeStore()
	store.putUser(testUser())
	store.createRegistrationErr = storeErr
	rp := newFakeRelyingParty()
	rp.createdCredential = &webauthn.Credential{ID: []byte("credential-1")}
	service := newTestService(t, store, rp)
	service.parseCreationResponse = func([]byte) (*protocol.ParsedCredentialCreationData, error) {
		return &protocol.ParsedCredentialCreationData{}, nil
	}

	result, err := service.FinishRegistration(context.Background(), FinishRegistrationRequest{
		PrincipalID: testPrincipalID,
		User:        testUser(),
		SessionData: webauthn.SessionData{Challenge: "registration-challenge"},
		Response:    []byte(`{"id":"credential-1"}`),
	})

	require.ErrorIs(t, err, authkit.ErrInternal)
	require.ErrorIs(t, err, storeErr)
	assert.Empty(t, store.createdRegistrations)
	assert.Empty(t, result)
}

func TestFinishRegistrationRejectsMalformedResponses(t *testing.T) {
	store := newFakeStore()
	user := testUser()
	store.putUser(user)
	service := newTestService(t, store, newFakeRelyingParty())

	result, err := service.FinishRegistration(context.Background(), FinishRegistrationRequest{
		PrincipalID: testPrincipalID,
		User:        user,
		SessionData: webauthn.SessionData{Challenge: "registration-challenge"},
		Response:    []byte(`not-json`),
	})

	require.ErrorIs(t, err, authkit.ErrUnauthenticated)
	assert.Empty(t, result)
}

func TestFinishRegistrationRequiresSessionUser(t *testing.T) {
	service := newTestService(t, newFakeStore(), newFakeRelyingParty())

	result, err := service.FinishRegistration(context.Background(), FinishRegistrationRequest{
		PrincipalID: testPrincipalID,
		SessionData: webauthn.SessionData{Challenge: "registration-challenge"},
		Response:    []byte(`{"id":"credential-1"}`),
	})

	require.ErrorIs(t, err, authkit.ErrUnauthenticated)
	assert.Empty(t, result)
}

func TestBeginLoginReturnsDiscoverableAssertion(t *testing.T) {
	rp := newFakeRelyingParty()
	service := newTestService(t, newFakeStore(), rp)

	result, err := service.BeginLogin(context.Background(), BeginLoginRequest{})

	require.NoError(t, err)
	assert.Same(t, rp.assertion, result.Assertion)
	assert.Equal(t, *rp.loginSession, result.SessionData)
	assert.Equal(t, protocol.VerificationRequired, result.SessionData.UserVerification)
	assert.Equal(t, protocol.VerificationRequired, result.Assertion.Response.UserVerification)
}

func TestFinishLoginUpdatesCredentialAndReturnsIdentity(t *testing.T) {
	store := newFakeStore()
	user := testUser()
	store.putUser(user)
	store.putCredential(Credential{
		RPID:         testRPID,
		PrincipalID:  testPrincipalID,
		UserHandle:   user.Handle,
		CredentialID: []byte("credential-1"),
		WebAuthn: webauthn.Credential{
			ID:        []byte("credential-1"),
			PublicKey: []byte("public-key"),
		},
	})
	store.putLink(identityForCredential(testRPID, user.Handle, []byte("credential-1")), testPrincipalID)
	rp := newFakeRelyingParty()
	rp.validateUserHandle = user.Handle
	rp.validatedCredential = &webauthn.Credential{
		ID:        []byte("credential-1"),
		PublicKey: []byte("public-key"),
		Authenticator: webauthn.Authenticator{
			SignCount: 7,
		},
	}
	service := newTestService(t, store, rp)
	response := []byte(`{"id":"credential-1"}`)
	service.parseAssertionResponse = func(data []byte) (*protocol.ParsedCredentialAssertionData, error) {
		assert.Equal(t, response, data)
		return &protocol.ParsedCredentialAssertionData{}, nil
	}

	result, err := service.FinishLogin(context.Background(), FinishLoginRequest{
		SessionData: webauthn.SessionData{Challenge: "login-challenge"},
		Response:    response,
	})

	require.NoError(t, err)
	require.NotNil(t, store.updatedCredential)
	assert.Equal(t, []byte("credential-1"), store.updatedCredential.CredentialID)
	assert.Equal(t, uint32(7), store.updatedCredential.WebAuthn.Authenticator.SignCount)
	assert.Equal(t, *store.updatedCredential, result.Credential)
	assert.Equal(t, user, result.User)
	assert.Equal(t, authkit.Identity{
		Provider:     "passkey:" + testRPID,
		Subject:      base64.RawURLEncoding.EncodeToString(user.Handle),
		CredentialID: base64.RawURLEncoding.EncodeToString([]byte("credential-1")),
	}, result.Identity)
	require.NotNil(t, rp.validatedHandlerUser)
	assert.Equal(t, user.Handle, rp.validatedHandlerUser.WebAuthnID())
	assert.Equal(t, webauthn.SessionData{
		Challenge:        "login-challenge",
		UserVerification: protocol.VerificationRequired,
	}, rp.validateSession)
}

func TestFinishLoginOverridesDowngradedUserVerification(t *testing.T) {
	store := newFakeStore()
	user := testUser()
	store.putUser(user)
	store.putCredential(testCredential(user))
	store.putLink(identityForCredential(testRPID, user.Handle, []byte("credential-1")), testPrincipalID)
	rp := newFakeRelyingParty()
	rp.validateUserHandle = user.Handle
	rp.validatedCredential = &webauthn.Credential{ID: []byte("credential-1")}
	service := newTestService(t, store, rp)
	service.parseAssertionResponse = func([]byte) (*protocol.ParsedCredentialAssertionData, error) {
		return &protocol.ParsedCredentialAssertionData{}, nil
	}

	result, err := service.FinishLogin(context.Background(), FinishLoginRequest{
		SessionData: webauthn.SessionData{
			Challenge:        "login-challenge",
			UserVerification: protocol.VerificationDiscouraged,
		},
		Response: []byte(`{"id":"credential-1"}`),
	})

	require.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.Equal(t, protocol.VerificationRequired, rp.validateSession.UserVerification)
}

func TestFinishLoginWrapsCredentialUpdateFailures(t *testing.T) {
	updateErr := errors.New("update failed")
	store := newFakeStore()
	user := testUser()
	store.putUser(user)
	store.putCredential(testCredential(user))
	store.putLink(identityForCredential(testRPID, user.Handle, []byte("credential-1")), testPrincipalID)
	store.updateCredentialErr = updateErr
	rp := newFakeRelyingParty()
	rp.validateUserHandle = user.Handle
	rp.validatedCredential = &webauthn.Credential{ID: []byte("credential-1")}
	service := newTestService(t, store, rp)
	service.parseAssertionResponse = func([]byte) (*protocol.ParsedCredentialAssertionData, error) {
		return &protocol.ParsedCredentialAssertionData{}, nil
	}

	result, err := service.FinishLogin(context.Background(), FinishLoginRequest{
		SessionData: webauthn.SessionData{Challenge: "login-challenge"},
		Response:    []byte(`{"id":"credential-1"}`),
	})

	require.ErrorIs(t, err, authkit.ErrInternal)
	require.ErrorIs(t, err, updateErr)
	assert.Empty(t, result)
}

func TestFinishLoginRejectsCloneWarning(t *testing.T) {
	store := newFakeStore()
	user := testUser()
	store.putUser(user)
	store.putCredential(Credential{
		RPID:         testRPID,
		PrincipalID:  testPrincipalID,
		UserHandle:   user.Handle,
		CredentialID: []byte("credential-1"),
		WebAuthn: webauthn.Credential{
			ID:        []byte("credential-1"),
			PublicKey: []byte("public-key"),
		},
	})
	rp := newFakeRelyingParty()
	rp.validateUserHandle = user.Handle
	rp.validatedCredential = &webauthn.Credential{
		ID: []byte("credential-1"),
		Authenticator: webauthn.Authenticator{
			CloneWarning: true,
		},
	}
	service := newTestService(t, store, rp)
	service.parseAssertionResponse = func([]byte) (*protocol.ParsedCredentialAssertionData, error) {
		return &protocol.ParsedCredentialAssertionData{}, nil
	}

	result, err := service.FinishLogin(context.Background(), FinishLoginRequest{
		SessionData: webauthn.SessionData{Challenge: "login-challenge"},
		Response:    []byte(`{"id":"credential-1"}`),
	})

	require.ErrorIs(t, err, authkit.ErrUnauthenticated)
	require.ErrorIs(t, err, ErrCloneWarning)
	require.NotNil(t, store.updatedCredential)
	assert.True(t, store.updatedCredential.WebAuthn.Authenticator.CloneWarning)
	assert.Empty(t, result)
}

func TestFinishLoginReturnsInternalWhenCloneWarningUpdateFails(t *testing.T) {
	updateErr := errors.New("update failed")
	store := newFakeStore()
	user := testUser()
	store.putUser(user)
	store.putCredential(testCredential(user))
	store.updateCredentialErr = updateErr
	rp := newFakeRelyingParty()
	rp.validateUserHandle = user.Handle
	rp.validatedCredential = &webauthn.Credential{
		ID: []byte("credential-1"),
		Authenticator: webauthn.Authenticator{
			CloneWarning: true,
		},
	}
	service := newTestService(t, store, rp)
	service.parseAssertionResponse = func([]byte) (*protocol.ParsedCredentialAssertionData, error) {
		return &protocol.ParsedCredentialAssertionData{}, nil
	}

	result, err := service.FinishLogin(context.Background(), FinishLoginRequest{
		SessionData: webauthn.SessionData{Challenge: "login-challenge"},
		Response:    []byte(`{"id":"credential-1"}`),
	})

	require.ErrorIs(t, err, authkit.ErrInternal)
	require.ErrorIs(t, err, updateErr)
	require.NotErrorIs(t, err, ErrCloneWarning)
	assert.Empty(t, result)
}

func TestFinishLoginRejectsMismatchedStoredCredential(t *testing.T) {
	store := newFakeStore()
	user := testUser()
	store.putUser(user)
	store.putCredential(Credential{
		RPID:         testRPID,
		PrincipalID:  "principal_other",
		UserHandle:   user.Handle,
		CredentialID: []byte("credential-1"),
		WebAuthn: webauthn.Credential{
			ID:        []byte("credential-1"),
			PublicKey: []byte("public-key"),
		},
	})
	rp := newFakeRelyingParty()
	rp.validateUserHandle = user.Handle
	rp.validatedCredential = &webauthn.Credential{ID: []byte("credential-1")}
	service := newTestService(t, store, rp)
	service.parseAssertionResponse = func([]byte) (*protocol.ParsedCredentialAssertionData, error) {
		return &protocol.ParsedCredentialAssertionData{}, nil
	}

	result, err := service.FinishLogin(context.Background(), FinishLoginRequest{
		SessionData: webauthn.SessionData{Challenge: "login-challenge"},
		Response:    []byte(`{"id":"credential-1"}`),
	})

	require.ErrorIs(t, err, authkit.ErrInternal)
	assert.Nil(t, rp.validatedHandlerUser)
	assert.Nil(t, store.updatedCredential)
	assert.Empty(t, result)
}

func TestFinishLoginRejectsValidatedCredentialNotLoadedFromStore(t *testing.T) {
	store := newFakeStore()
	user := testUser()
	store.putUser(user)
	store.putCredential(Credential{
		RPID:         testRPID,
		PrincipalID:  testPrincipalID,
		UserHandle:   user.Handle,
		CredentialID: []byte("credential-1"),
		WebAuthn: webauthn.Credential{
			ID:        []byte("credential-1"),
			PublicKey: []byte("public-key"),
		},
	})
	rp := newFakeRelyingParty()
	rp.validateUserHandle = user.Handle
	rp.validatedCredential = &webauthn.Credential{ID: []byte("credential-2")}
	service := newTestService(t, store, rp)
	service.parseAssertionResponse = func([]byte) (*protocol.ParsedCredentialAssertionData, error) {
		return &protocol.ParsedCredentialAssertionData{}, nil
	}

	result, err := service.FinishLogin(context.Background(), FinishLoginRequest{
		SessionData: webauthn.SessionData{Challenge: "login-challenge"},
		Response:    []byte(`{"id":"credential-2"}`),
	})

	require.ErrorIs(t, err, authkit.ErrInternal)
	require.NotErrorIs(t, err, authkit.ErrUnresolvedIdentity)
	assert.Nil(t, store.updatedCredential)
	assert.Empty(t, result)
}

func TestFinishLoginReturnsUnresolvedIdentityForUnlinkedCredential(t *testing.T) {
	store := newFakeStore()
	user := testUser()
	store.putUser(user)
	store.putCredential(testCredential(user))
	rp := newFakeRelyingParty()
	rp.validateUserHandle = user.Handle
	rp.validatedCredential = &webauthn.Credential{ID: []byte("credential-1")}
	service := newTestService(t, store, rp)
	service.parseAssertionResponse = func([]byte) (*protocol.ParsedCredentialAssertionData, error) {
		return &protocol.ParsedCredentialAssertionData{}, nil
	}

	result, err := service.FinishLogin(context.Background(), FinishLoginRequest{
		SessionData: webauthn.SessionData{Challenge: "login-challenge"},
		Response:    []byte(`{"id":"credential-1"}`),
	})

	require.ErrorIs(t, err, authkit.ErrUnresolvedIdentity)
	require.NotErrorIs(t, err, authkit.ErrUnauthenticated)
	assert.Empty(t, result)
}

func TestFinishLoginRejectsDivergedIdentityLink(t *testing.T) {
	store := newFakeStore()
	user := testUser()
	store.putUser(user)
	store.putCredential(testCredential(user))
	store.putLink(identityForCredential(testRPID, user.Handle, []byte("credential-1")), "principal_other")
	rp := newFakeRelyingParty()
	rp.validateUserHandle = user.Handle
	rp.validatedCredential = &webauthn.Credential{ID: []byte("credential-1")}
	service := newTestService(t, store, rp)
	service.parseAssertionResponse = func([]byte) (*protocol.ParsedCredentialAssertionData, error) {
		return &protocol.ParsedCredentialAssertionData{}, nil
	}

	result, err := service.FinishLogin(context.Background(), FinishLoginRequest{
		SessionData: webauthn.SessionData{Challenge: "login-challenge"},
		Response:    []byte(`{"id":"credential-1"}`),
	})

	require.ErrorIs(t, err, authkit.ErrInternal)
	assert.Nil(t, store.updatedCredential)
	assert.Empty(t, result)
}

func TestFinishLoginWrapsDiscoverableLookupFailures(t *testing.T) {
	lookupErr := errors.New("lookup failed")
	store := newFakeStore()
	store.findUserByHandleErr = lookupErr
	rp := newFakeRelyingParty()
	rp.validateUserHandle = []byte("user-handle")
	service := newTestService(t, store, rp)
	service.parseAssertionResponse = func([]byte) (*protocol.ParsedCredentialAssertionData, error) {
		return &protocol.ParsedCredentialAssertionData{}, nil
	}

	result, err := service.FinishLogin(context.Background(), FinishLoginRequest{
		SessionData: webauthn.SessionData{Challenge: "login-challenge"},
		Response:    []byte(`{"id":"credential-1"}`),
	})

	require.ErrorIs(t, err, authkit.ErrInternal)
	require.ErrorIs(t, err, lookupErr)
	assert.Empty(t, result)
}

func newTestService(t *testing.T, store Store, rp *fakeRelyingParty) *Service {
	t.Helper()

	service, err := newService(store, testConfig(), rp)
	require.NoError(t, err)

	return service
}

func testConfig() Config {
	return Config{
		RPID:          testRPID,
		RPDisplayName: "Authkit Test",
		RPOrigins:     []string{"https://example.test"},
	}
}

func testUser() User {
	return User{
		RPID:        testRPID,
		PrincipalID: testPrincipalID,
		Handle:      []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
		Name:        "ada@example.test",
		DisplayName: "Ada Lovelace",
	}
}

func testCredential(user User) Credential {
	credentialID := []byte("credential-1")

	return Credential{
		RPID:         user.RPID,
		PrincipalID:  user.PrincipalID,
		UserHandle:   user.Handle,
		CredentialID: credentialID,
		WebAuthn: webauthn.Credential{
			ID:        credentialID,
			PublicKey: []byte("public-key"),
		},
	}
}

type fakeRelyingParty struct {
	creation            *protocol.CredentialCreation
	registrationSession *webauthn.SessionData
	registrationUser    webauthn.User

	createdCredential       *webauthn.Credential
	createCredentialUser    webauthn.User
	createCredentialSession webauthn.SessionData
	createCredentialErr     error

	assertion    *protocol.CredentialAssertion
	loginSession *webauthn.SessionData

	validateUserHandle    []byte
	validatedHandlerUser  webauthn.User
	validatedCredential   *webauthn.Credential
	validateSession       webauthn.SessionData
	validateCredentialErr error
}

func newFakeRelyingParty() *fakeRelyingParty {
	return &fakeRelyingParty{
		creation:            &protocol.CredentialCreation{},
		registrationSession: &webauthn.SessionData{Challenge: "registration-challenge"},
		assertion:           &protocol.CredentialAssertion{},
		loginSession:        &webauthn.SessionData{Challenge: "login-challenge"},
	}
}

func (f *fakeRelyingParty) BeginRegistration(
	user webauthn.User,
	opts ...webauthn.RegistrationOption,
) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	f.registrationUser = user
	for _, opt := range opts {
		opt(&f.creation.Response)
	}
	session := *f.registrationSession
	session.UserVerification = f.creation.Response.AuthenticatorSelection.UserVerification
	f.registrationSession = &session

	return f.creation, f.registrationSession, nil
}

func (f *fakeRelyingParty) CreateCredential(
	user webauthn.User,
	session webauthn.SessionData,
	_ *protocol.ParsedCredentialCreationData,
) (*webauthn.Credential, error) {
	f.createCredentialUser = user
	f.createCredentialSession = session
	if f.createCredentialErr != nil {
		return nil, f.createCredentialErr
	}

	return f.createdCredential, nil
}

func (f *fakeRelyingParty) BeginDiscoverableLogin(
	opts ...webauthn.LoginOption,
) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	for _, opt := range opts {
		opt(&f.assertion.Response)
	}
	session := *f.loginSession
	session.UserVerification = f.assertion.Response.UserVerification
	f.loginSession = &session

	return f.assertion, f.loginSession, nil
}

func (f *fakeRelyingParty) ValidatePasskeyLogin(
	handler webauthn.DiscoverableUserHandler,
	session webauthn.SessionData,
	_ *protocol.ParsedCredentialAssertionData,
) (webauthn.User, *webauthn.Credential, error) {
	f.validateSession = session
	if f.validateCredentialErr != nil {
		return nil, nil, f.validateCredentialErr
	}

	user, err := handler([]byte("credential-1"), f.validateUserHandle)
	if err != nil {
		return nil, nil, err
	}
	f.validatedHandlerUser = user

	return user, f.validatedCredential, nil
}

type fakeStore struct {
	usersByPrincipal map[string]User
	usersByHandle    map[string]User
	credentials      map[string][]Credential
	links            map[string]authkit.ExternalIdentity

	createdRegistrations []Registration
	updatedCredential    *Credential
	calls                []string

	createRegistrationErr    error
	createRegistrationResult func(RegistrationResult) RegistrationResult
	updateCredentialErr      error
	findUserByHandleErr      error
	resolveIdentityErr       error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		usersByPrincipal: make(map[string]User),
		usersByHandle:    make(map[string]User),
		credentials:      make(map[string][]Credential),
		links:            make(map[string]authkit.ExternalIdentity),
	}
}

func (s *fakeStore) ResolveIdentity(
	_ context.Context,
	identity authkit.Identity,
) (*authkit.Principal, error) {
	if s.resolveIdentityErr != nil {
		return nil, s.resolveIdentityErr
	}

	link, ok := s.links[identityKey(identity.Provider, identity.Subject)]
	if !ok {
		return nil, authkit.ErrUnresolvedIdentity
	}

	return &authkit.Principal{
		ID: link.PrincipalID,
	}, nil
}

func (s *fakeStore) FindUserByPrincipal(_ context.Context, rpID string, principalID string) (User, error) {
	user, ok := s.usersByPrincipal[rpID+"\x00"+principalID]
	if !ok {
		return User{}, ErrUserNotFound
	}

	return cloneUser(user), nil
}

func (s *fakeStore) FindUserByHandle(_ context.Context, rpID string, handle []byte) (User, error) {
	if s.findUserByHandleErr != nil {
		return User{}, s.findUserByHandleErr
	}

	user, ok := s.usersByHandle[handleKey(rpID, handle)]
	if !ok {
		return User{}, ErrUserNotFound
	}

	return cloneUser(user), nil
}

func (s *fakeStore) ListCredentials(_ context.Context, rpID string, userHandle []byte) ([]Credential, error) {
	return cloneCredentials(s.credentials[handleKey(rpID, userHandle)]), nil
}

func (s *fakeStore) CreateRegistration(
	_ context.Context,
	registration Registration,
) (RegistrationResult, error) {
	s.calls = append(s.calls, "createRegistration")
	if s.createRegistrationErr != nil {
		return RegistrationResult{}, s.createRegistrationErr
	}

	cloned := cloneRegistration(registration)
	s.createdRegistrations = append(s.createdRegistrations, cloned)
	s.putUser(cloned.User)
	s.putCredential(cloned.Credential)
	link := authkit.ExternalIdentity{
		Provider:    cloned.Identity.Provider,
		Subject:     cloned.Identity.Subject,
		PrincipalID: cloned.User.PrincipalID,
	}
	s.links[identityKey(link.Provider, link.Subject)] = link

	result := RegistrationResult{
		User:       cloneUser(cloned.User),
		Credential: cloneCredential(cloned.Credential),
		Link:       link,
	}
	if s.createRegistrationResult != nil {
		result = s.createRegistrationResult(result)
	}

	return result, nil
}

func (s *fakeStore) UpdateCredentialAfterLogin(_ context.Context, credential Credential) error {
	if s.updateCredentialErr != nil {
		return s.updateCredentialErr
	}

	clone := cloneCredential(credential)
	s.updatedCredential = &clone

	return nil
}

func (s *fakeStore) putUser(user User) {
	cloned := cloneUser(user)
	s.usersByPrincipal[cloned.RPID+"\x00"+cloned.PrincipalID] = cloned
	s.usersByHandle[handleKey(cloned.RPID, cloned.Handle)] = cloned
}

func (s *fakeStore) putCredential(credential Credential) {
	cloned := cloneCredential(credential)
	key := handleKey(cloned.RPID, cloned.UserHandle)
	s.credentials[key] = append(s.credentials[key], cloned)
}

func (s *fakeStore) putLink(identity authkit.Identity, principalID string) {
	s.links[identityKey(identity.Provider, identity.Subject)] = authkit.ExternalIdentity{
		Provider:    identity.Provider,
		Subject:     identity.Subject,
		PrincipalID: principalID,
	}
}

func handleKey(rpID string, handle []byte) string {
	return rpID + "\x00" + string(handle)
}

func identityKey(provider string, subject string) string {
	return provider + "\x00" + subject
}
