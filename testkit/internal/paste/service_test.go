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
	secondPasteID = "paste-2"
	maxTestBytes  = 5
)

func TestServiceCreatesPaste(t *testing.T) {
	service := newTestService(t, firstPasteID, fixedTime())

	created, err := service.Create(context.Background(), paste.CreatePasteRequest{
		Title:  "  Example paste  ",
		Body:   "hello, pastebin",
		Syntax: "  text  ",
	})

	require.NoError(t, err)
	assert.Equal(t, firstPasteID, created.ID)
	assert.Equal(t, "Example paste", created.Title)
	assert.Equal(t, "hello, pastebin", created.Body)
	assert.Equal(t, "text", created.Syntax)
	assert.Equal(t, fixedTime(), created.CreatedAt)

	found, err := service.Read(context.Background(), firstPasteID)
	require.NoError(t, err)
	assert.Equal(t, created, found)
}

func TestServiceRejectsInvalidBodies(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		assertErr func(*testing.T, error)
	}{
		{
			name: "empty body",
			body: " \n\t ",
			assertErr: func(t *testing.T, err error) {
				t.Helper()
				assert.ErrorIs(t, err, paste.ErrEmptyBody)
			},
		},
		{
			name: "body above limit",
			body: "abcdef",
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

			_, err := service.Create(context.Background(), paste.CreatePasteRequest{
				Body: tt.body,
			})

			tt.assertErr(t, err)
		})
	}
}

func TestServiceReturnsMissingPasteError(t *testing.T) {
	service := newTestService(t, firstPasteID, fixedTime())

	_, err := service.Read(context.Background(), "missing")

	assert.ErrorIs(t, err, paste.ErrPasteNotFound)
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

	_, err = service.Create(context.Background(), paste.CreatePasteRequest{Body: "older"})
	require.NoError(t, err)
	now = now.Add(time.Minute)
	_, err = service.Create(context.Background(), paste.CreatePasteRequest{Body: "newer"})
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
