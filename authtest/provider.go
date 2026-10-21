// Package authtest is a stand-in for the identity provider an API trusts, for
// the API's tests. It publishes discovery and a key set, grants
// client-credentials tokens, and signs RFC 9068 access tokens the way Authelia
// does: typed at+jwt, RS256, and with no subject on a service's token.
package authtest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/datapointchris/goapiauth"
)

const keyID = "authtest"

// Provider is a running stand-in. URL is its issuer.
type Provider struct {
	URL string

	key    *rsa.PrivateKey
	mu     sync.Mutex
	client map[string]registered
}

type registered struct {
	secret string
	scopes []string
}

// signingKey is generated once per test binary, because an RSA key costs tens
// of milliseconds and a suite stands up many providers.
var signingKey = sync.OnceValues(func() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) })

// NewProvider starts a provider that lives as long as t.
func NewProvider(t testing.TB) *Provider {
	t.Helper()
	key, err := signingKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p := &Provider{key: key, client: map[string]registered{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"issuer": p.URL, "jwks_uri": p.URL + "/jwks.json", "token_endpoint": p.URL + "/token",
		})
	})
	mux.HandleFunc("GET /jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: key.Public(), KeyID: keyID, Algorithm: string(jose.RS256), Use: "sig",
		}}})
	})
	mux.HandleFunc("POST /token", p.grant)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	p.URL = server.URL
	return p
}

// Register lets clientID authenticate with secret and be granted scopes.
func (p *Provider) Register(clientID, secret string, scopes ...string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.client[clientID] = registered{secret: secret, scopes: scopes}
}

// grant answers the client-credentials grant, authenticated with HTTP Basic as
// RFC 6749 § 2.3.1 has every provider accept.
func (p *Provider) grant(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := r.BasicAuth()
	p.mu.Lock()
	client, known := p.client[id]
	p.mu.Unlock()
	if !ok || !known || client.secret != secret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if r.PostFormValue("grant_type") != "client_credentials" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	asked := strings.Fields(r.PostFormValue("scope"))
	for _, scope := range asked {
		if !slices.Contains(client.scopes, scope) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_scope"})
			return
		}
	}
	token, err := p.signTyped("at+jwt", map[string]any{"client_id": id, "scp": asked})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token, "token_type": "bearer", "expires_in": 300, "scope": strings.Join(asked, " "),
	})
}

// Person is the token a person's device login as clientID would hold.
func (p *Provider) Person(t testing.TB, clientID, subject string) string {
	t.Helper()
	return p.Sign(t, "at+jwt", map[string]any{"client_id": clientID, "sub": subject, "scp": []string{"openid", "offline_access"}})
}

// Sign is a token typed typ, carrying claims over the issuer and expiry every
// token the provider grants has. A claim set to nil is left out.
func (p *Provider) Sign(t testing.TB, typ string, claims map[string]any) string {
	t.Helper()
	token, err := p.signTyped(typ, claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return token
}

// Verifier is a goapiauth.Verifier reading this provider, for the person and
// service client prefixes the caller's production code uses.
func (p *Provider) Verifier(t testing.TB, personPrefix, servicePrefix string) *goapiauth.Verifier {
	t.Helper()
	v, err := goapiauth.NewVerifier(context.Background(), goapiauth.Config{
		Issuer: p.URL, PersonPrefix: personPrefix, ServicePrefix: servicePrefix,
	})
	if err != nil {
		t.Fatalf("read the stand-in provider: %v", err)
	}
	return v
}

// Bearer is a client sending token with every request.
func Bearer(token string) *http.Client {
	return &http.Client{Transport: bearer{token: token, base: http.DefaultTransport}}
}

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(req)
}

func (p *Provider) signTyped(typ string, claims map[string]any) (string, error) {
	now := time.Now()
	body := map[string]any{"iss": p.URL, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	for k, v := range claims {
		if v == nil {
			delete(body, k)
			continue
		}
		body[k] = v
	}
	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("kid", keyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: p.key}, opts)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return signed.CompactSerialize()
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
