package passkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/meigma/authkit"
)

const (
	providerPrefix             = "passkey:"
	userHandleBytes            = 64
	defaultRegistrationTimeout = 5 * time.Minute
	defaultLoginTimeout        = 5 * time.Minute
)

type relyingParty interface {
	BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (
		*protocol.CredentialCreation,
		*webauthn.SessionData,
		error,
	)
	CreateCredential(
		user webauthn.User,
		session webauthn.SessionData,
		parsedResponse *protocol.ParsedCredentialCreationData,
	) (*webauthn.Credential, error)
	BeginDiscoverableLogin(opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	ValidatePasskeyLogin(
		handler webauthn.DiscoverableUserHandler,
		session webauthn.SessionData,
		parsedResponse *protocol.ParsedCredentialAssertionData,
	) (webauthn.User, *webauthn.Credential, error)
}

type creationParser func([]byte) (*protocol.ParsedCredentialCreationData, error)
type assertionParser func([]byte) (*protocol.ParsedCredentialAssertionData, error)

// Service runs WebAuthn passkey registration and login ceremonies.
type Service struct {
	store                  Store
	config                 Config
	rp                     relyingParty
	parseCreationResponse  creationParser
	parseAssertionResponse assertionParser
}

// NewService constructs a passkey service for config.
func NewService(store Store, config Config) (*Service, error) {
	if store == nil {
		return nil, errors.New("passkey: store is required")
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	rp, err := webauthn.New(&webauthn.Config{
		RPID:                   config.RPID,
		RPDisplayName:          config.RPDisplayName,
		RPOrigins:              cloneStrings(config.RPOrigins),
		AuthenticatorSelection: passkeyAuthenticatorSelection(),
		Timeouts: webauthn.TimeoutsConfig{
			Registration: enforcedTimeout(registrationTimeout(config)),
			Login:        enforcedTimeout(loginTimeout(config)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: create relying party: %w", err)
	}

	return newService(store, config, rp)
}

func newService(store Store, config Config, rp relyingParty) (*Service, error) {
	if store == nil {
		return nil, errors.New("passkey: store is required")
	}
	if rp == nil {
		return nil, errors.New("passkey: relying party is required")
	}
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	return &Service{
		store:                  store,
		config:                 cloneConfig(config),
		rp:                     rp,
		parseCreationResponse:  protocol.ParseCredentialCreationResponseBytes,
		parseAssertionResponse: protocol.ParseCredentialRequestResponseBytes,
	}, nil
}

// BeginRegistration starts a passkey registration ceremony for an existing authkit principal.
func (s *Service) BeginRegistration(
	ctx context.Context,
	req BeginRegistrationRequest,
) (BeginRegistrationResult, error) {
	if err := ctx.Err(); err != nil {
		return BeginRegistrationResult{}, err
	}
	if req.PrincipalID == "" {
		return BeginRegistrationResult{}, errors.New("passkey: principal ID is required")
	}
	if req.Name == "" {
		return BeginRegistrationResult{}, errors.New("passkey: user name is required")
	}
	if req.DisplayName == "" {
		return BeginRegistrationResult{}, errors.New("passkey: user display name is required")
	}

	user, credentials, err := s.registrationUser(ctx, req)
	if err != nil {
		return BeginRegistrationResult{}, err
	}

	webUser, err := newWebAuthnUser(user, credentials)
	if err != nil {
		return BeginRegistrationResult{}, internalError("validate credentials", err)
	}

	creation, session, err := s.rp.BeginRegistration(
		webUser,
		webauthn.WithAuthenticatorSelection(passkeyAuthenticatorSelection()),
		webauthn.WithExclusions(credentialExclusions(webUser)),
	)
	if err != nil {
		return BeginRegistrationResult{}, internalError("begin registration", err)
	}
	if creation == nil || session == nil {
		return BeginRegistrationResult{}, internalError(
			"begin registration",
			errors.New("relying party returned nil result"),
		)
	}

	return BeginRegistrationResult{
		Creation:    creation,
		SessionData: *session,
		User:        cloneUser(user),
	}, nil
}

// FinishRegistration verifies a passkey registration response and stores its credential.
func (s *Service) FinishRegistration(
	ctx context.Context,
	req FinishRegistrationRequest,
) (FinishRegistrationResult, error) {
	if err := ctx.Err(); err != nil {
		return FinishRegistrationResult{}, err
	}
	if req.PrincipalID == "" {
		return FinishRegistrationResult{}, errors.New("passkey: principal ID is required")
	}
	user, err := s.finishRegistrationUser(req)
	if err != nil {
		return FinishRegistrationResult{}, err
	}
	if len(req.Response) == 0 {
		return FinishRegistrationResult{}, unauthenticated("registration response is required")
	}

	credentials, err := s.store.ListCredentials(ctx, s.config.RPID, user.Handle)
	if err != nil {
		return FinishRegistrationResult{}, internalError("list credentials", err)
	}

	parsed, err := s.parseCreationResponse(req.Response)
	if err != nil {
		return FinishRegistrationResult{}, unauthenticated("invalid registration response")
	}
	webUser, err := newWebAuthnUser(user, credentials)
	if err != nil {
		return FinishRegistrationResult{}, internalError("validate credentials", err)
	}

	session := sessionRequiringUserVerification(req.SessionData)
	upstreamCredential, err := s.rp.CreateCredential(webUser, session, parsed)
	if err != nil {
		return FinishRegistrationResult{}, unauthenticated("registration verification failed")
	}
	if upstreamCredential == nil {
		return FinishRegistrationResult{}, internalError(
			"finish registration",
			errors.New("relying party returned nil credential"),
		)
	}

	identity := identityForCredential(s.config.RPID, user.Handle, upstreamCredential.ID)
	credential := Credential{
		RPID:         s.config.RPID,
		PrincipalID:  user.PrincipalID,
		UserHandle:   cloneBytes(user.Handle),
		CredentialID: cloneBytes(upstreamCredential.ID),
		WebAuthn:     cloneWebAuthnCredential(*upstreamCredential),
	}
	expectedRegistration := Registration{
		User:       user,
		Credential: credential,
		Identity:   identity,
	}
	registration, err := s.store.CreateRegistration(ctx, expectedRegistration)
	if err != nil {
		if errors.Is(err, ErrCredentialExists) || errors.Is(err, ErrUserExists) {
			return FinishRegistrationResult{}, err
		}
		return FinishRegistrationResult{}, internalError("create registration", err)
	}
	if err := validateRegistrationResult(registration, expectedRegistration); err != nil {
		return FinishRegistrationResult{}, internalError("validate registration result", err)
	}

	return FinishRegistrationResult{
		Identity:   identity,
		Link:       registration.Link,
		Credential: cloneCredential(registration.Credential),
	}, nil
}

// BeginLogin starts a discoverable passkey login ceremony.
func (s *Service) BeginLogin(ctx context.Context, _ BeginLoginRequest) (BeginLoginResult, error) {
	if err := ctx.Err(); err != nil {
		return BeginLoginResult{}, err
	}

	assertion, session, err := s.rp.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return BeginLoginResult{}, internalError("begin login", err)
	}
	if assertion == nil || session == nil {
		return BeginLoginResult{}, internalError("begin login", errors.New("relying party returned nil result"))
	}

	return BeginLoginResult{
		Assertion:   assertion,
		SessionData: *session,
	}, nil
}

// FinishLogin verifies a discoverable passkey login response.
func (s *Service) FinishLogin(ctx context.Context, req FinishLoginRequest) (FinishLoginResult, error) {
	if err := ctx.Err(); err != nil {
		return FinishLoginResult{}, err
	}
	if len(req.Response) == 0 {
		return FinishLoginResult{}, unauthenticated("login response is required")
	}

	parsed, err := s.parseAssertionResponse(req.Response)
	if err != nil {
		return FinishLoginResult{}, unauthenticated("invalid login response")
	}
	session := sessionRequiringUserVerification(req.SessionData)
	user, upstreamCredential, err := s.rp.ValidatePasskeyLogin(s.discoverableUserHandler(ctx), session, parsed)
	if err != nil {
		if errors.Is(err, authkit.ErrInternal) {
			return FinishLoginResult{}, err
		}
		return FinishLoginResult{}, unauthenticated("login verification failed")
	}
	if upstreamCredential == nil {
		return FinishLoginResult{}, internalError("finish login", errors.New("relying party returned nil credential"))
	}
	passkeyUser, ok := user.(webAuthnUser)
	if !ok {
		return FinishLoginResult{}, internalError("finish login", errors.New("unexpected WebAuthn user type"))
	}
	storedCredential, ok := credentialByID(passkeyUser.credentials, upstreamCredential.ID)
	if !ok {
		return FinishLoginResult{}, internalError(
			"match credential",
			fmt.Errorf("credential %q is not stored for passkey user", credentialIDString(upstreamCredential.ID)),
		)
	}

	credential := Credential{
		RPID:         storedCredential.RPID,
		PrincipalID:  storedCredential.PrincipalID,
		UserHandle:   cloneBytes(storedCredential.UserHandle),
		CredentialID: cloneBytes(storedCredential.CredentialID),
		WebAuthn:     cloneWebAuthnCredential(*upstreamCredential),
	}
	if upstreamCredential.Authenticator.CloneWarning {
		if err := s.store.UpdateCredentialAfterLogin(ctx, credential); err != nil {
			return FinishLoginResult{}, internalError("update credential after clone warning", err)
		}

		return FinishLoginResult{}, cloneWarning()
	}

	identity := identityForCredential(s.config.RPID, storedCredential.UserHandle, storedCredential.CredentialID)
	if err := s.validateLinkedPrincipal(ctx, identity, passkeyUser.user.PrincipalID); err != nil {
		return FinishLoginResult{}, err
	}
	if err := s.store.UpdateCredentialAfterLogin(ctx, credential); err != nil {
		return FinishLoginResult{}, internalError("update credential after login", err)
	}

	return FinishLoginResult{
		Identity:   identity,
		User:       cloneUser(passkeyUser.user),
		Credential: cloneCredential(credential),
	}, nil
}

func (s *Service) validateLinkedPrincipal(
	ctx context.Context,
	identity authkit.Identity,
	wantPrincipalID string,
) error {
	principal, err := s.store.ResolveIdentity(ctx, identity)
	if errors.Is(err, authkit.ErrUnresolvedIdentity) {
		return err
	}
	if err != nil {
		return internalError("resolve identity", err)
	}
	if principal == nil {
		return internalError("resolve identity", errors.New("store returned nil principal"))
	}
	if principal.ID != wantPrincipalID {
		return internalError(
			"resolve identity",
			fmt.Errorf("identity resolved to principal %q, want %q", principal.ID, wantPrincipalID),
		)
	}

	return nil
}

func (s *Service) registrationUser(
	ctx context.Context,
	req BeginRegistrationRequest,
) (User, []Credential, error) {
	user, err := s.store.FindUserByPrincipal(ctx, s.config.RPID, req.PrincipalID)
	if err == nil {
		credentials, listErr := s.store.ListCredentials(ctx, s.config.RPID, user.Handle)
		if listErr != nil {
			return User{}, nil, internalError("list credentials", listErr)
		}

		return cloneUser(user), credentials, nil
	}
	if !errors.Is(err, ErrUserNotFound) {
		return User{}, nil, internalError("find user by principal", err)
	}

	handle := make([]byte, userHandleBytes)
	if _, err := rand.Read(handle); err != nil {
		return User{}, nil, internalError("generate user handle", err)
	}

	user = User{
		RPID:        s.config.RPID,
		PrincipalID: req.PrincipalID,
		Handle:      handle,
		Name:        req.Name,
		DisplayName: req.DisplayName,
	}

	return cloneUser(user), nil, nil
}

func (s *Service) finishRegistrationUser(req FinishRegistrationRequest) (User, error) {
	user := req.User
	if user.RPID == "" && user.PrincipalID == "" && len(user.Handle) == 0 {
		return User{}, unauthenticated("registration user session data is required")
	}
	if user.RPID != s.config.RPID {
		return User{}, unauthenticated("registration user relying party does not match")
	}
	if user.PrincipalID != req.PrincipalID {
		return User{}, unauthenticated("registration user principal does not match")
	}
	if len(user.Handle) == 0 {
		return User{}, unauthenticated("registration user handle is required")
	}
	if user.Name == "" {
		return User{}, unauthenticated("registration user name is required")
	}
	if user.DisplayName == "" {
		return User{}, unauthenticated("registration user display name is required")
	}

	return cloneUser(user), nil
}

func (s *Service) discoverableUserHandler(ctx context.Context) webauthn.DiscoverableUserHandler {
	return func(_, userHandle []byte) (webauthn.User, error) {
		user, err := s.store.FindUserByHandle(ctx, s.config.RPID, userHandle)
		if errors.Is(err, ErrUserNotFound) {
			return nil, err
		}
		if err != nil {
			return nil, internalError("find user by handle", err)
		}
		credentials, err := s.store.ListCredentials(ctx, s.config.RPID, user.Handle)
		if err != nil {
			return nil, internalError("list credentials", err)
		}

		webUser, err := newWebAuthnUser(user, credentials)
		if err != nil {
			return nil, internalError("validate credentials", err)
		}

		return webUser, nil
	}
}

func validateConfig(config Config) error {
	if strings.TrimSpace(config.RPID) == "" {
		return errors.New("passkey: RP ID is required")
	}
	if strings.TrimSpace(config.RPDisplayName) == "" {
		return errors.New("passkey: RP display name is required")
	}
	if len(config.RPOrigins) == 0 {
		return errors.New("passkey: RP origins are required")
	}
	for i, origin := range config.RPOrigins {
		if strings.TrimSpace(origin) == "" {
			return fmt.Errorf("passkey: RP origin %d is required", i)
		}
	}
	if config.RegistrationTimeout < 0 {
		return errors.New("passkey: registration timeout must be positive")
	}
	if config.LoginTimeout < 0 {
		return errors.New("passkey: login timeout must be positive")
	}

	return nil
}

func passkeyAuthenticatorSelection() protocol.AuthenticatorSelection {
	return protocol.AuthenticatorSelection{
		RequireResidentKey: protocol.ResidentKeyRequired(),
		ResidentKey:        protocol.ResidentKeyRequirementRequired,
		UserVerification:   protocol.VerificationRequired,
	}
}

func credentialExclusions(user webAuthnUser) []protocol.CredentialDescriptor {
	credentials := user.WebAuthnCredentials()
	if len(credentials) == 0 {
		return nil
	}

	return webauthn.Credentials(credentials).CredentialDescriptors()
}

func sessionRequiringUserVerification(session webauthn.SessionData) webauthn.SessionData {
	session.UserVerification = protocol.VerificationRequired

	return session
}

func validateRegistrationResult(result RegistrationResult, expected Registration) error {
	if err := validateRegistrationUser(result.User, expected.User); err != nil {
		return err
	}
	if err := validateRegistrationCredential(result.Credential, expected.Credential); err != nil {
		return err
	}
	if err := validateRegistrationLink(result.Link, expected); err != nil {
		return err
	}

	return nil
}

func validateRegistrationUser(got User, want User) error {
	switch {
	case got.RPID != want.RPID:
		return fmt.Errorf("registration user RP ID %q, want %q", got.RPID, want.RPID)
	case got.PrincipalID != want.PrincipalID:
		return fmt.Errorf("registration user principal %q, want %q", got.PrincipalID, want.PrincipalID)
	case !bytes.Equal(got.Handle, want.Handle):
		return errors.New("registration user handle does not match verified ceremony")
	}

	return nil
}

func validateRegistrationCredential(got Credential, want Credential) error {
	switch {
	case got.RPID != want.RPID:
		return fmt.Errorf("registration credential RP ID %q, want %q", got.RPID, want.RPID)
	case got.PrincipalID != want.PrincipalID:
		return fmt.Errorf("registration credential principal %q, want %q", got.PrincipalID, want.PrincipalID)
	case !bytes.Equal(got.UserHandle, want.UserHandle):
		return errors.New("registration credential user handle does not match verified ceremony")
	case !bytes.Equal(got.CredentialID, want.CredentialID):
		return errors.New("registration credential ID does not match verified ceremony")
	case len(got.WebAuthn.ID) > 0 && !bytes.Equal(got.WebAuthn.ID, want.CredentialID):
		return errors.New("registration credential WebAuthn ID does not match verified ceremony")
	}

	return nil
}

func validateRegistrationLink(got authkit.ExternalIdentity, expected Registration) error {
	switch {
	case got.Provider != expected.Identity.Provider:
		return fmt.Errorf("registration link provider %q, want %q", got.Provider, expected.Identity.Provider)
	case got.Subject != expected.Identity.Subject:
		return fmt.Errorf("registration link subject %q, want %q", got.Subject, expected.Identity.Subject)
	case got.PrincipalID != expected.User.PrincipalID:
		return fmt.Errorf("registration link principal %q, want %q", got.PrincipalID, expected.User.PrincipalID)
	}

	return nil
}

func enforcedTimeout(timeout time.Duration) webauthn.TimeoutConfig {
	return webauthn.TimeoutConfig{
		Enforce:    true,
		Timeout:    timeout,
		TimeoutUVD: timeout,
	}
}

func registrationTimeout(config Config) time.Duration {
	if config.RegistrationTimeout != 0 {
		return config.RegistrationTimeout
	}

	return defaultRegistrationTimeout
}

func loginTimeout(config Config) time.Duration {
	if config.LoginTimeout != 0 {
		return config.LoginTimeout
	}

	return defaultLoginTimeout
}

func identityForCredential(rpID string, userHandle []byte, credentialID []byte) authkit.Identity {
	return authkit.Identity{
		Provider:     providerPrefix + rpID,
		Subject:      base64.RawURLEncoding.EncodeToString(userHandle),
		CredentialID: base64.RawURLEncoding.EncodeToString(credentialID),
	}
}

func credentialIDString(credentialID []byte) string {
	return base64.RawURLEncoding.EncodeToString(credentialID)
}
