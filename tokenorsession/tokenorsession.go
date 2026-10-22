// Package tokenorsession admits a request to a Go web API that carries either
// a bearer token goapiauth verifies or a gobrowserlogin session.
//
// A command-line client sends the provider's access token. The API's own
// single-page front end sends the session cookie gobrowserlogin set, with its
// CSRF header. A request carrying a bearer credential is judged on it alone
// and never reaches the session, so a caller cannot pair a junk token with a
// stolen cookie.
package tokenorsession

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/datapointchris/gobrowserlogin"

	"github.com/datapointchris/goapiauth"
	"github.com/datapointchris/goapiauth/internal/publicpath"
	"github.com/datapointchris/goapiauth/internal/refusal"
)

// Sessions is what Require authenticates a browser with, as
// *gobrowserlogin.Sessions does.
type Sessions interface {
	Authenticate(r *http.Request) (gobrowserlogin.Identity, error)
}

// Require passes a request to next when it carries a bearer token verifier
// accepts, or a session sessions authenticates, and puts the caller's
// goapiauth.Identity on its context. A session's Identity carries its Subject
// and Groups. A request for one of the public paths, or for
// goapiauth.ProtectedResourcePath, passes with neither: the browser login's
// routes are reached before a session exists.
//
// A bearer request is answered as goapiauth.RequireBearer answers it, and
// every refusal carries one of goapiauth's codes. A request with no credential
// at all is a 401, a session cookie without the CSRF header is a 403, and a
// session store that cannot be read is a 503.
func Require(verifier goapiauth.TokenVerifier, sessions Sessions, log *slog.Logger, public ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		bearer := goapiauth.RequireBearer(verifier, log)(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if publicpath.Admits(r.URL.Path, public) {
				next.ServeHTTP(w, r)
				return
			}
			if goapiauth.BearerToken(r.Header.Get("Authorization")) != "" {
				bearer.ServeHTTP(w, r)
				return
			}
			identity, err := sessions.Authenticate(r)
			switch {
			case errors.Is(err, gobrowserlogin.ErrNoSession):
				refusal.Unauthorized(w, "", goapiauth.CodeMissingToken, "the request carries no credential this API accepts")
			case errors.Is(err, gobrowserlogin.ErrNoCSRFHeader):
				refusal.Write(w, http.StatusForbidden, goapiauth.CodeMissingCSRFHeader,
					"a request carrying the session cookie must send the "+gobrowserlogin.CSRFHeader+" header")
			case r.Context().Err() != nil:
				log.InfoContext(r.Context(), "request ended before its session was read", "err", err, "path", r.URL.Path)
				refusal.Write(w, http.StatusServiceUnavailable, goapiauth.CodeSessionStoreUnavailable,
					"the request ended before its session was read")
			case err != nil:
				log.ErrorContext(r.Context(), "session store unavailable", "err", err, "path", r.URL.Path)
				refusal.Write(w, http.StatusServiceUnavailable, goapiauth.CodeSessionStoreUnavailable, "the session store is unavailable")
			default:
				caller := goapiauth.Identity{Subject: identity.Subject, Groups: identity.Groups}
				next.ServeHTTP(w, r.WithContext(goapiauth.WithIdentity(r.Context(), caller)))
			}
		})
	}
}
