package tokenorsession_test

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/datapointchris/gobrowserlogin"

	"github.com/datapointchris/goapiauth"
	"github.com/datapointchris/goapiauth/authtest"
	"github.com/datapointchris/goapiauth/tokenorsession"
)

// sessions answers every request with the same identity or error, and counts
// how often it was asked.
type sessions struct {
	identity gobrowserlogin.Identity
	err      error
	asked    int
}

func (s *sessions) Authenticate(*http.Request) (gobrowserlogin.Identity, error) {
	s.asked++
	return s.identity, s.err
}

var whoami = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	identity, _ := goapiauth.IdentityFrom(r.Context())
	_, _ = w.Write([]byte(identity.Subject))
})

func serve(t *testing.T, handler http.Handler, path, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, http.NoBody)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestRequireAdmitsATokenOrASessionAndNeverPairsThem(t *testing.T) {
	provider := authtest.NewProvider(t)
	verifier := provider.Verifier(t, "acme-cli-", "")

	t.Run("a session passes with its subject and groups", func(t *testing.T) {
		s := &sessions{identity: gobrowserlogin.Identity{Subject: "chris", Groups: []string{"admin"}}}
		handler := tokenorsession.Require(verifier, s, slog.Default())(goapiauth.RequireGroup("admin", whoami))
		if rec := serve(t, handler, "/api", ""); rec.Code != 200 || rec.Body.String() != "chris" {
			t.Errorf("answered %d %q, want chris through the admin group", rec.Code, rec.Body)
		}
	})

	t.Run("a token passes without asking the session", func(t *testing.T) {
		s := &sessions{err: gobrowserlogin.ErrNoSession}
		rec := serve(t, tokenorsession.Require(verifier, s, slog.Default())(whoami), "/api", "Bearer "+provider.Person(t, "acme-cli-desk", "chris"))
		if rec.Code != 200 || rec.Body.String() != "chris" || s.asked != 0 {
			t.Errorf("answered %d %q and asked the session %d times, want chris and none", rec.Code, rec.Body, s.asked)
		}
	})

	t.Run("a rejected token never falls through to a session", func(t *testing.T) {
		s := &sessions{identity: gobrowserlogin.Identity{Subject: "chris"}}
		rec := serve(t, tokenorsession.Require(verifier, s, slog.Default())(whoami), "/api", "Bearer not.a.token")
		if rec.Code != 401 || s.asked != 0 {
			t.Errorf("answered %d and asked the session %d times, want 401 and none", rec.Code, s.asked)
		}
	})

	for name, tc := range map[string]struct {
		err    error
		status int
	}{
		"no session":           {gobrowserlogin.ErrNoSession, 401},
		"no CSRF header":       {gobrowserlogin.ErrNoCSRFHeader, 403},
		"a session store down": {errors.New("connection refused"), 503},
	} {
		t.Run(name, func(t *testing.T) {
			rec := serve(t, tokenorsession.Require(verifier, &sessions{err: tc.err}, slog.Default())(whoami), "/api", "")
			if rec.Code != tc.status {
				t.Errorf("answered %d, want %d", rec.Code, tc.status)
			}
		})
	}

	t.Run("the login is reached before a session exists", func(t *testing.T) {
		s := &sessions{err: gobrowserlogin.ErrNoSession}
		rec := serve(t, tokenorsession.Require(verifier, s, slog.Default(), "/api/auth/login")(whoami), "/api/auth/login", "")
		if rec.Code != 200 || s.asked != 0 {
			t.Errorf("answered %d and asked the session %d times, want 200 and none", rec.Code, s.asked)
		}
	})
}
