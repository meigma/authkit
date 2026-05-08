package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meigma/authkit/apikey"
)

func TestNotesAppAuthorizesRequests(t *testing.T) {
	app := newTestApp(t)
	unlinkedToken := issueUnlinkedToken(t, app)

	tests := []struct {
		name          string
		path          string
		authorization string
		wantStatus    int
		wantBody      string
	}{
		{
			name:          "allows seeded token to read allowed note",
			path:          "/notes/allowed",
			authorization: bearer(app.seedToken),
			wantStatus:    http.StatusOK,
			wantBody:      "This note is readable by the seeded service principal.\n",
		},
		{
			name:          "denies seeded token for note outside policy",
			path:          "/notes/denied",
			authorization: bearer(app.seedToken),
			wantStatus:    http.StatusForbidden,
			wantBody:      "Forbidden\n",
		},
		{
			name:       "requires bearer token",
			path:       "/notes/allowed",
			wantStatus: http.StatusUnauthorized,
			wantBody:   "Unauthorized\n",
		},
		{
			name:          "rejects malformed bearer token",
			path:          "/notes/allowed",
			authorization: bearer("invalid"),
			wantStatus:    http.StatusUnauthorized,
			wantBody:      "Unauthorized\n",
		},
		{
			name:          "rejects valid token without identity link",
			path:          "/notes/allowed",
			authorization: bearer(unlinkedToken),
			wantStatus:    http.StatusUnauthorized,
			wantBody:      "Unauthorized\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}

			recorder := httptest.NewRecorder()
			app.ServeHTTP(recorder, req)

			assert.Equal(t, tt.wantStatus, recorder.Code)
			assert.Equal(t, tt.wantBody, recorder.Body.String())
		})
	}
}

func newTestApp(t *testing.T) *notesApp {
	t.Helper()

	now := time.Date(2026, time.May, 7, 20, 45, 0, 0, time.UTC)
	app, err := newNotesApp(context.Background(), func() time.Time {
		return now
	})
	require.NoError(t, err)

	return app
}

func issueUnlinkedToken(t *testing.T, app *notesApp) string {
	t.Helper()

	issued, err := app.tokenService.IssueToken(context.Background(), apikey.IssueRequest{
		PrincipalID: app.principal.ID,
		Name:        "unlinked token",
		ExpiresAt:   app.tokenExpiresAt,
	})
	require.NoError(t, err)

	return issued.Plaintext
}

func bearer(token string) string {
	return "Bearer " + token
}
