package onboarding_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit"
	"github.com/meigma/authkit/onboarding"
)

const (
	testPrincipalID   = "principal_1"
	testProvider      = "passkey"
	testSubject       = "user-handle-1"
	testPrincipalName = "Test User"
	testRoleID        = "reader"
)

var errLinkConflict = errors.New("identity already linked to another principal")

func TestNewServiceAllowsSparseOptions(t *testing.T) {
	tests := []struct {
		name string
		opts onboarding.Options
	}{
		{
			name: "no collaborators",
		},
		{
			name: "attach collaborators",
			opts: onboarding.Options{
				PrincipalFinder: newFakePrincipalFinder(),
				IdentityLinker:  newFakeIdentityLinker(),
			},
		},
		{
			name: "provision collaborator",
			opts: onboarding.Options{
				IdentityProvisioner: newFakeIdentityProvisioner(),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := onboarding.NewService(tt.opts)

			assert.NotNil(t, service)
		})
	}
}

func TestServiceMethodsRequirePorts(t *testing.T) {
	tests := []struct {
		name string
		opts onboarding.Options
		run  func(*onboarding.Service) error
		want string
	}{
		{
			name: "attach identity missing principal finder",
			run: func(service *onboarding.Service) error {
				_, err := service.AttachIdentity(context.Background(), attachRequest())

				return err
			},
			want: "onboarding: principal finder is required",
		},
		{
			name: "attach identity missing identity linker",
			opts: onboarding.Options{
				PrincipalFinder: newFakePrincipalFinder(),
			},
			run: func(service *onboarding.Service) error {
				_, err := service.AttachIdentity(context.Background(), attachRequest())

				return err
			},
			want: "onboarding: identity linker is required",
		},
		{
			name: "provision principal missing identity provisioner",
			run: func(service *onboarding.Service) error {
				_, err := service.ProvisionPrincipal(context.Background(), provisionRequest())

				return err
			},
			want: "onboarding: identity provisioner is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := onboarding.NewService(tt.opts)

			err := tt.run(service)

			require.Error(t, err)
			assert.EqualError(t, err, tt.want)
		})
	}
}

func TestAttachIdentityValidatesRequest(t *testing.T) {
	service := onboarding.NewService(onboarding.Options{
		PrincipalFinder: newFakePrincipalFinder(),
		IdentityLinker:  newFakeIdentityLinker(),
	})

	tests := []struct {
		name string
		req  onboarding.AttachIdentityRequest
		want string
	}{
		{
			name: "missing identity provider",
			req: onboarding.AttachIdentityRequest{
				Identity: authkit.Identity{
					Subject: testSubject,
				},
				PrincipalID: testPrincipalID,
			},
			want: "onboarding: identity provider is required",
		},
		{
			name: "missing identity subject",
			req: onboarding.AttachIdentityRequest{
				Identity: authkit.Identity{
					Provider: testProvider,
				},
				PrincipalID: testPrincipalID,
			},
			want: "onboarding: identity subject is required",
		},
		{
			name: "missing principal ID",
			req: onboarding.AttachIdentityRequest{
				Identity: verifiedIdentity(),
			},
			want: "onboarding: principal ID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.AttachIdentity(context.Background(), tt.req)

			require.EqualError(t, err, tt.want)
			assert.Empty(t, result)
		})
	}
}

func TestAttachIdentityFindsPrincipalThenLinksIdentity(t *testing.T) {
	finder := newFakePrincipalFinder()
	linker := newFakeIdentityLinker()
	service := onboarding.NewService(onboarding.Options{
		PrincipalFinder: finder,
		IdentityLinker:  linker,
	})
	req := attachRequest()

	result, err := service.AttachIdentity(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, finder.principal, result.Principal)
	assert.Equal(t, linker.link, result.Link)
	assert.Equal(t, []string{testPrincipalID}, finder.findIDs)
	assert.Equal(t, []authkit.LinkIdentityRequest{
		{
			Provider:    testProvider,
			Subject:     testSubject,
			PrincipalID: testPrincipalID,
		},
	}, linker.requests)
}

func TestAttachIdentityPropagatesPrincipalNotFound(t *testing.T) {
	finder := newFakePrincipalFinder()
	finder.err = authkit.ErrPrincipalNotFound
	linker := newFakeIdentityLinker()
	service := onboarding.NewService(onboarding.Options{
		PrincipalFinder: finder,
		IdentityLinker:  linker,
	})

	result, err := service.AttachIdentity(context.Background(), attachRequest())

	require.ErrorIs(t, err, authkit.ErrPrincipalNotFound)
	assert.Empty(t, result)
	assert.Empty(t, linker.requests)
}

func TestAttachIdentityPropagatesLinkConflict(t *testing.T) {
	linker := newFakeIdentityLinker()
	linker.err = errLinkConflict
	service := onboarding.NewService(onboarding.Options{
		PrincipalFinder: newFakePrincipalFinder(),
		IdentityLinker:  linker,
	})

	result, err := service.AttachIdentity(context.Background(), attachRequest())

	require.ErrorIs(t, err, errLinkConflict)
	assert.Empty(t, result)
}

func TestProvisionPrincipalValidatesIdentity(t *testing.T) {
	service := onboarding.NewService(onboarding.Options{
		IdentityProvisioner: newFakeIdentityProvisioner(),
	})

	tests := []struct {
		name string
		req  onboarding.ProvisionPrincipalRequest
		want string
	}{
		{
			name: "missing identity provider",
			req: onboarding.ProvisionPrincipalRequest{
				Identity: authkit.Identity{
					Subject: testSubject,
				},
			},
			want: "onboarding: identity provider is required",
		},
		{
			name: "missing identity subject",
			req: onboarding.ProvisionPrincipalRequest{
				Identity: authkit.Identity{
					Provider: testProvider,
				},
			},
			want: "onboarding: identity subject is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.ProvisionPrincipal(context.Background(), tt.req)

			require.EqualError(t, err, tt.want)
			assert.Empty(t, result)
		})
	}
}

func TestProvisionPrincipalDelegatesToIdentityProvisioner(t *testing.T) {
	provisioner := newFakeIdentityProvisioner()
	service := onboarding.NewService(onboarding.Options{
		IdentityProvisioner: provisioner,
	})
	req := provisionRequest()

	result, err := service.ProvisionPrincipal(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, provisioner.result.Principal, result.Principal)
	assert.Equal(t, provisioner.result.Link, result.Link)
	assert.True(t, result.Created)
	assert.Equal(t, []authkit.ProvisionIdentityRequest{
		{
			Identity:       req.Identity,
			Principal:      req.Principal,
			InitialRoleIDs: req.InitialRoleIDs,
		},
	}, provisioner.requests)
}

func TestServicePropagatesContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	t.Run("attach identity", func(t *testing.T) {
		service := onboarding.NewService(onboarding.Options{
			PrincipalFinder: newFakePrincipalFinder(),
			IdentityLinker:  newFakeIdentityLinker(),
		})

		_, err := service.AttachIdentity(ctx, attachRequest())

		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("provision principal", func(t *testing.T) {
		service := onboarding.NewService(onboarding.Options{
			IdentityProvisioner: newFakeIdentityProvisioner(),
		})

		_, err := service.ProvisionPrincipal(ctx, provisionRequest())

		require.ErrorIs(t, err, context.Canceled)
	})
}

func verifiedIdentity() authkit.Identity {
	return authkit.Identity{
		Provider:     testProvider,
		Subject:      testSubject,
		CredentialID: "credential_1",
	}
}

func testPrincipal() authkit.Principal {
	return authkit.Principal{
		ID:          testPrincipalID,
		Kind:        authkit.PrincipalKindUser,
		DisplayName: testPrincipalName,
	}
}

func testLink() authkit.ExternalIdentity {
	return authkit.ExternalIdentity{
		Provider:    testProvider,
		Subject:     testSubject,
		PrincipalID: testPrincipalID,
	}
}

func attachRequest() onboarding.AttachIdentityRequest {
	return onboarding.AttachIdentityRequest{
		Identity:    verifiedIdentity(),
		PrincipalID: testPrincipalID,
	}
}

func provisionRequest() onboarding.ProvisionPrincipalRequest {
	return onboarding.ProvisionPrincipalRequest{
		Identity: verifiedIdentity(),
		Principal: authkit.CreatePrincipalRequest{
			Kind:        authkit.PrincipalKindUser,
			DisplayName: testPrincipalName,
		},
		InitialRoleIDs: []string{testRoleID},
	}
}

type fakePrincipalFinder struct {
	findIDs   []string
	principal authkit.Principal
	err       error
}

func newFakePrincipalFinder() *fakePrincipalFinder {
	return &fakePrincipalFinder{
		principal: testPrincipal(),
	}
}

func (f *fakePrincipalFinder) FindPrincipal(
	ctx context.Context,
	id string,
) (authkit.Principal, error) {
	if err := ctx.Err(); err != nil {
		return authkit.Principal{}, err
	}

	f.findIDs = append(f.findIDs, id)
	if f.err != nil {
		return authkit.Principal{}, f.err
	}

	return f.principal, nil
}

type fakeIdentityLinker struct {
	requests []authkit.LinkIdentityRequest
	link     authkit.ExternalIdentity
	err      error
}

func newFakeIdentityLinker() *fakeIdentityLinker {
	return &fakeIdentityLinker{
		link: testLink(),
	}
}

func (f *fakeIdentityLinker) LinkIdentity(
	ctx context.Context,
	req authkit.LinkIdentityRequest,
) (authkit.ExternalIdentity, error) {
	if err := ctx.Err(); err != nil {
		return authkit.ExternalIdentity{}, err
	}

	f.requests = append(f.requests, req)
	if f.err != nil {
		return authkit.ExternalIdentity{}, f.err
	}

	return f.link, nil
}

type fakeIdentityProvisioner struct {
	requests []authkit.ProvisionIdentityRequest
	result   authkit.ProvisionIdentityResult
	err      error
}

func newFakeIdentityProvisioner() *fakeIdentityProvisioner {
	return &fakeIdentityProvisioner{
		result: authkit.ProvisionIdentityResult{
			Principal: testPrincipal(),
			Link:      testLink(),
			Created:   true,
		},
	}
}

func (f *fakeIdentityProvisioner) ProvisionIdentity(
	ctx context.Context,
	req authkit.ProvisionIdentityRequest,
) (authkit.ProvisionIdentityResult, error) {
	if err := ctx.Err(); err != nil {
		return authkit.ProvisionIdentityResult{}, err
	}

	f.requests = append(f.requests, req)
	if f.err != nil {
		return authkit.ProvisionIdentityResult{}, f.err
	}

	return f.result, nil
}
