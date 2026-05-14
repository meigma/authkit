// Package storetest contains shared behavior tests for testkit paste stores.
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit/testkit/internal/paste"
)

const (
	firstPasteID  = "paste-1"
	recentLimit   = 2
	secondPasteID = "paste-2"
	thirdOffset   = 2
	thirdPasteID  = "paste-3"
)

// Run runs the shared paste repository behavior suite.
func Run(t *testing.T, newRepo func(*testing.T) paste.Repository) {
	t.Helper()

	t.Run("create and find paste", func(t *testing.T) {
		repo := newRepo(t)
		created := newPaste(firstPasteID, "Example", "hello", "text", firstTime())

		require.NoError(t, repo.Create(context.Background(), created))
		found, err := repo.Find(context.Background(), firstPasteID)

		require.NoError(t, err)
		assert.Equal(t, created, found)
	})

	t.Run("missing paste returns not found", func(t *testing.T) {
		repo := newRepo(t)

		_, err := repo.Find(context.Background(), "missing")

		assert.ErrorIs(t, err, paste.ErrPasteNotFound)
	})

	t.Run("duplicate paste ID is rejected", func(t *testing.T) {
		repo := newRepo(t)
		created := newPaste(firstPasteID, "Example", "hello", "text", firstTime())

		require.NoError(t, repo.Create(context.Background(), created))
		err := repo.Create(context.Background(), created)

		assert.ErrorIs(t, err, paste.ErrDuplicatePasteID)
	})

	t.Run("recent list is newest first and limited", func(t *testing.T) {
		repo := newRepo(t)

		require.NoError(t, repo.Create(context.Background(), newPaste(firstPasteID, "Old", "one", "", firstTime())))
		require.NoError(t, repo.Create(context.Background(), newPaste(secondPasteID, "New", "two", "", secondTime())))
		require.NoError(
			t,
			repo.Create(context.Background(), newPaste(thirdPasteID, "Newest", "three", "", thirdTime())),
		)

		recent, err := repo.ListRecent(context.Background(), recentLimit)

		require.NoError(t, err)
		require.Len(t, recent, recentLimit)
		assert.Equal(t, thirdPasteID, recent[0].ID)
		assert.Equal(t, secondPasteID, recent[1].ID)
	})
}

func newPaste(id string, title string, body string, syntax string, createdAt time.Time) paste.Paste {
	return paste.Paste{
		ID:        id,
		Title:     title,
		Body:      body,
		Syntax:    syntax,
		CreatedAt: createdAt,
	}
}

func firstTime() time.Time {
	return time.Date(2026, time.May, 14, 10, 0, 0, 0, time.UTC)
}

func secondTime() time.Time {
	return firstTime().Add(time.Minute)
}

func thirdTime() time.Time {
	return firstTime().Add(thirdOffset * time.Minute)
}
