package goapiauth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/datapointchris/goapiauth/internal/refusal"
)

// TokenVerifier is what RequireBearer checks a token with, as *Verifier and
// *Connecting do.
type TokenVerifier interface {
	Verify(ctx context.Context, raw string) (Identity, error)
}

type contextKey struct{}

// RequireBearer passes a request to next only when it carries a bearer token
// verifier accepts, and puts the token's Identity on its context. A request
// for one of the public paths, or for ProtectedResourcePath, passes with
// none: a CLI reads the metadata before it holds a token.
//
// A missing or rejected token is a 401 carrying the RFC 6750 Bearer
// challenge, and a provider that cannot be read is a 503. Each is logged with
// its reason, which the body does not carry. A request whose caller went away
// before its token was verified gets no answer.
func RequireBearer(verifier TokenVerifier, log *slog.Logger, public ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isPublic(r, public) {
				next.ServeHTTP(w, r)
				return
			}
			ctx := r.Context()
			raw := BearerToken(r.Header.Get("Authorization"))
			if raw == "" {
				w.Header().Set("WWW-Authenticate", "Bearer")
				refusal.Write(w, http.StatusUnauthorized, refusal.MissingToken, "the request carries no bearer token")
				return
			}
			identity, err := verifier.Verify(ctx, raw)
			switch {
			case err == nil:
				next.ServeHTTP(w, r.WithContext(WithIdentity(ctx, identity)))
			case ctx.Err() != nil:
				log.InfoContext(ctx, "request ended before its token was verified", "err", err, "path", r.URL.Path)
			case errors.Is(err, ErrProviderUnavailable):
				log.ErrorContext(ctx, "identity provider unavailable", "err", err, "path", r.URL.Path)
				refusal.Write(w, http.StatusServiceUnavailable, refusal.IdentityProviderUnavailable,
					"the identity provider is unavailable, so no token can be verified")
			default:
				log.WarnContext(ctx, "bearer token rejected", "err", err, "path", r.URL.Path)
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				refusal.Write(w, http.StatusUnauthorized, refusal.InvalidToken, "the bearer token is not valid")
			}
		})
	}
}

func isPublic(r *http.Request, public []string) bool {
	return r.URL.Path == ProtectedResourcePath || slices.Contains(public, r.URL.Path)
}

// WithIdentity is ctx carrying identity, as RequireBearer leaves it. A
// session middleware, or a development server running none, sets it the same
// way.
func WithIdentity(ctx context.Context, identity Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, identity)
}

// IdentityFrom is the identity established for the request.
func IdentityFrom(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(contextKey{}).(Identity)
	return identity, ok
}

// BearerToken is the credential in an Authorization header, or "" when the
// header is absent or names another scheme.
func BearerToken(header string) string {
	const prefix = "Bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

// RequireGroup passes a request to next only when its Identity is in group,
// and refuses every other with a 403.
func RequireGroup(group string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, _ := IdentityFrom(r.Context())
		if !slices.Contains(identity.Groups, group) {
			refusal.Write(w, http.StatusForbidden, "", "this needs membership in the "+group+" group")
			return
		}
		next.ServeHTTP(w, r)
	})
}
