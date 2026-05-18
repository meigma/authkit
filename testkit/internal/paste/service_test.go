package paste_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit/testkit/internal/paste"
	"github.com/meigma/authkit/testkit/internal/store/memory"
)

const (
	firstPasteID  = "paste-1"
	ownerID       = "principal-owner"
	secondPasteID = "paste-2"
	maxTestBytes  = 5
)

func TestServiceCreatesPaste(t *testing.T) {
	service := newTestService(t, firstPasteID, fixedTime())

	created, err := service.Create(context.Background(), paste.CreatePasteRequest{
		Title:            "  Example paste  ",
		Body:             "hello, pastebin",
		Syntax:           "  text  ",
		OwnerPrincipalID: "  " + ownerID + "  ",
	})

	require.NoError(t, err)
	assert.Equal(t, firstPasteID, created.ID)
	assert.Equal(t, "Example paste", created.Title)
	assert.Equal(t, "hello, pastebin", created.Body)
	assert.Equal(t, "text", created.Syntax)
	assert.Equal(t, ownerID, created.OwnerPrincipalID)
	assert.Equal(t, fixedTime(), created.CreatedAt)

	found, err := service.Read(context.Background(), firstPasteID)
	require.NoError(t, err)
	assert.Equal(t, created, found)
}

func TestServiceUpdatesPaste(t *testing.T) {
	service := newTestService(t, firstPasteID, fixedTime())
	created, err := service.Create(context.Background(), paste.CreatePasteRequest{
		Title:            "Original",
		Body:             "hello, pastebin",
		Syntax:           "text",
		OwnerPrincipalID: ownerID,
	})
	require.NoError(t, err)

	updated, err := service.Update(context.Background(), paste.UpdatePasteRequest{
		ID:               firstPasteID,
		Title:            "  Updated  ",
		Body:             "edited paste",
		Syntax:           "  markdown  ",
		OwnerPrincipalID: ownerID,
	})

	require.NoError(t, err)
	assert.Equal(t, firstPasteID, updated.ID)
	assert.Equal(t, "Updated", updated.Title)
	assert.Equal(t, "edited paste", updated.Body)
	assert.Equal(t, "markdown", updated.Syntax)
	assert.Equal(t, ownerID, updated.OwnerPrincipalID)
	assert.Equal(t, created.CreatedAt, updated.CreatedAt)

	found, err := service.Read(context.Background(), firstPasteID)
	require.NoError(t, err)
	assert.Equal(t, updated, found)
}

func TestServiceDeletesPaste(t *testing.T) {
	service := newTestService(t, firstPasteID, fixedTime())
	_, err := service.Create(context.Background(), paste.CreatePasteRequest{
		Body:             "hello, pastebin",
		OwnerPrincipalID: ownerID,
	})
	require.NoError(t, err)

	require.NoError(t, service.Delete(context.Background(), paste.DeletePasteRequest{
		ID:               firstPasteID,
		OwnerPrincipalID: ownerID,
	}))
	_, err = service.Read(context.Background(), firstPasteID)

	require.ErrorIs(t, err, paste.ErrPasteNotFound)
}

func TestServiceRejectsInvalidBodies(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		body      string
		assertErr func(*testing.T, error)
	}{
		{
			name:      "create empty body",
			operation: "create",
			body:      " \n\t ",
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, paste.ErrEmptyBody)
			},
		},
		{
			name:      "create body above limit",
			operation: "create",
			body:      "abcdef",
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				var bodyErr paste.BodyTooLargeError
				require.ErrorAs(t, err, &bodyErr)
				assert.Equal(t, maxTestBytes, bodyErr.MaxBytes)
			},
		},
		{
			name:      "update empty body",
			operation: "update",
			body:      " \n\t ",
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				require.ErrorIs(t, err, paste.ErrEmptyBody)
			},
		},
		{
			name:      "update body above limit",
			operation: "update",
			body:      "abcdef",
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				var bodyErr paste.BodyTooLargeError
				require.ErrorAs(t, err, &bodyErr)
				assert.Equal(t, maxTestBytes, bodyErr.MaxBytes)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := newTestService(t, firstPasteID, fixedTime(), paste.WithMaxBodyBytes(maxTestBytes))

			var err error
			switch tt.operation {
			case "create":
				_, err = service.Create(context.Background(), paste.CreatePasteRequest{
					Body:             tt.body,
					OwnerPrincipalID: ownerID,
				})
			case "update":
				_, createErr := service.Create(context.Background(), paste.CreatePasteRequest{
					Body:             "abc",
					OwnerPrincipalID: ownerID,
				})
				require.NoError(t, createErr)
				_, err = service.Update(context.Background(), paste.UpdatePasteRequest{
					ID:               firstPasteID,
					Body:             tt.body,
					OwnerPrincipalID: ownerID,
				})
			}

			tt.assertErr(t, err)
		})
	}
}

func TestServiceRequiresOwner(t *testing.T) {
	service := newTestService(t, firstPasteID, fixedTime())

	_, createErr := service.Create(context.Background(), paste.CreatePasteRequest{Body: "hello"})
	_, updateErr := service.Update(context.Background(), paste.UpdatePasteRequest{
		ID:   firstPasteID,
		Body: "hello",
	})
	deleteErr := service.Delete(context.Background(), paste.DeletePasteRequest{ID: firstPasteID})

	require.ErrorIs(t, createErr, paste.ErrOwnerRequired)
	require.ErrorIs(t, updateErr, paste.ErrOwnerRequired)
	require.ErrorIs(t, deleteErr, paste.ErrOwnerRequired)
}

func TestServiceReturnsMissingPasteError(t *testing.T) {
	service := newTestService(t, secondPasteID, fixedTime())

	_, err := service.Read(context.Background(), "missing")

	require.ErrorIs(t, err, paste.ErrPasteNotFound)
}

func TestServiceReturnsMissingPasteErrorForUpdateAndDelete(t *testing.T) {
	service := newTestService(t, firstPasteID, fixedTime())

	_, updateErr := service.Update(context.Background(), paste.UpdatePasteRequest{
		ID:               "missing",
		Body:             "hello",
		OwnerPrincipalID: ownerID,
	})
	deleteErr := service.Delete(context.Background(), paste.DeletePasteRequest{
		ID:               "missing",
		OwnerPrincipalID: ownerID,
	})

	require.ErrorIs(t, updateErr, paste.ErrPasteNotFound)
	require.ErrorIs(t, deleteErr, paste.ErrPasteNotFound)
}

func TestServiceListsRecentPastesNewestFirst(t *testing.T) {
	repo := memory.NewStore()
	ids := sequentialIDs(firstPasteID, secondPasteID)
	now := fixedTime()
	service, err := paste.NewService(
		repo,
		paste.WithIDGenerator(ids.next),
		paste.WithClock(func() time.Time {
			return now
		}),
	)
	require.NoError(t, err)

	_, err = service.Create(context.Background(), paste.CreatePasteRequest{
		Body:             "older",
		OwnerPrincipalID: ownerID,
	})
	require.NoError(t, err)
	now = now.Add(time.Minute)
	_, err = service.Create(context.Background(), paste.CreatePasteRequest{
		Body:             "newer",
		OwnerPrincipalID: ownerID,
	})
	require.NoError(t, err)

	recent, err := service.ListRecent(context.Background(), paste.DefaultRecentLimit)

	require.NoError(t, err)
	require.Len(t, recent, 2)
	assert.Equal(t, secondPasteID, recent[0].ID)
	assert.Equal(t, firstPasteID, recent[1].ID)
}

func newTestService(t *testing.T, id string, now time.Time, opts ...paste.Option) *paste.Service {
	t.Helper()

	allOpts := []paste.Option{
		paste.WithIDGenerator(func() (string, error) {
			return id, nil
		}),
		paste.WithClock(func() time.Time {
			return now
		}),
	}
	allOpts = append(allOpts, opts...)

	service, err := paste.NewService(memory.NewStore(), allOpts...)
	require.NoError(t, err)

	return service
}

type idSequence struct {
	values []string
	nextID int
}

func sequentialIDs(ids ...string) *idSequence {
	return &idSequence{values: ids}
}

func (s *idSequence) next() (string, error) {
	if s.nextID >= len(s.values) {
		return "", errors.New("test: no more IDs")
	}

	id := s.values[s.nextID]
	s.nextID++

	return id, nil
}

func fixedTime() time.Time {
	return time.Date(2026, time.May, 14, 10, 0, 0, 0, time.UTC)
}
