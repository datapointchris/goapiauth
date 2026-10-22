package goapiauth_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/datapointchris/goapiauth"
	"github.com/datapointchris/goapiauth/authtest"
)

// refusalBody is the body every refusal answers with.
type refusalBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// call serves one request through handler and returns the response and its
// decoded refusal, which is empty for a success.
func call(t *testing.T, handler http.Handler, path, authorization string) (*http.Response, refusalBody) {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, http.NoBody)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var body refusalBody
	if rec.Code >= 400 {
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("%s answered %d with a body that is not a refusal: %v", path, rec.Code, err)
		}
	}
	return rec.Result(), body
}

// whoami answers 200 with the subject or client id the middleware put on the
// request.
var whoami = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	identity, ok := goapiauth.IdentityFrom(r.Context())
	if !ok {
		_, _ = w.Write([]byte("nobody"))
		return
	}
	_, _ = w.Write([]byte(identity.Subject + identity.ClientID))
})

func TestRequireBearerAnswersEachTokenWithWhatFixesIt(t *testing.T) {
	provider := authtest.NewProvider(t)
	verified := goapiauth.RequireBearer(provider.Verifier(t, "acme-cli-", ""), slog.Default(), "/health")(whoami)
	connecting, err := goapiauth.NewConnecting(goapiauth.Config{Issuer: provider.URL, PersonPrefix: "acme-cli-"})
	if err != nil {
		t.Fatal(err)
	}
	unread := goapiauth.RequireBearer(connecting, slog.Default())(whoami)

	for name, tc := range map[string]struct {
		handler       http.Handler
		path, header  string
		status        int
		code, connect string
	}{
		"a valid token":               {verified, "/api", "Bearer " + provider.Person(t, "acme-cli-desk", "chris"), 200, "", ""},
		"no token":                    {verified, "/api", "", 401, "missing_token", "Bearer"},
		"another scheme":              {verified, "/api", "Basic Y2hyaXM6eA==", 401, "missing_token", "Bearer"},
		"a bad token":                 {verified, "/api", "Bearer not.a.token", 401, "invalid_token", `Bearer error="invalid_token"`},
		"a provider not yet read":     {unread, "/api", "Bearer " + provider.Person(t, "acme-cli-desk", "chris"), 503, "identity_provider_unavailable", ""},
		"a public path with no token": {verified, "/health", "", 200, "", ""},
		"the metadata with no token":  {verified, goapiauth.ProtectedResourcePath, "", 200, "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			resp, body := call(t, tc.handler, tc.path, tc.header)
			if resp.StatusCode != tc.status || body.Code != tc.code {
				t.Errorf("answered %d %q, want %d %q", resp.StatusCode, body.Code, tc.status, tc.code)
			}
			if got := resp.Header.Get("WWW-Authenticate"); got != tc.connect {
				t.Errorf("WWW-Authenticate %q, want %q", got, tc.connect)
			}
		})
	}
}

func TestLimitServicesKeepsAServiceToItsScopes(t *testing.T) {
	provider := authtest.NewProvider(t)
	mux := http.NewServeMux()
	mux.Handle("GET /reports", whoami)
	mux.Handle("POST /reports", whoami)
	routes := map[string][]string{"acme.read": {"GET /reports"}}
	handler := goapiauth.RequireBearer(provider.Verifier(t, "acme-cli-", "acme-svc-"), slog.Default())(
		goapiauth.LimitServices(mux, routes, slog.Default()))
	reader := "Bearer " + provider.Sign(t, "at+jwt", map[string]any{"client_id": "acme-svc-reader", "scp": []string{"acme.read"}})

	if resp, _ := call(t, handler, "/reports", reader); resp.StatusCode != 200 {
		t.Errorf("a service reading inside its scope answered %d", resp.StatusCode)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/reports", http.NoBody)
	req.Header.Set("Authorization", reader)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), `"outside_service_scope"`) || !strings.Contains(rec.Body.String(), "GET /reports") {
		t.Errorf("a service writing outside its scope answered %d %s, want a 403 naming what it may reach", rec.Code, rec.Body)
	}
	if resp, _ := call(t, handler, "/reports", "Bearer "+provider.Person(t, "acme-cli-desk", "chris")); resp.StatusCode != 200 {
		t.Errorf("a person answered %d, want every route", resp.StatusCode)
	}
}

func TestRequireGroupAdmitsOnlyItsMembers(t *testing.T) {
	provider := authtest.NewProvider(t)
	handler := goapiauth.RequireBearer(provider.Verifier(t, "acme-cli-", ""), slog.Default())(goapiauth.RequireGroup("admin", whoami))
	token := func(groups ...string) string {
		return "Bearer " + provider.Sign(t, "at+jwt", map[string]any{"client_id": "acme-cli-desk", "sub": "chris", "groups": groups})
	}
	if resp, _ := call(t, handler, "/admin", token("admin", "users")); resp.StatusCode != 200 {
		t.Errorf("a member answered %d", resp.StatusCode)
	}
	if resp, _ := call(t, handler, "/admin", token("users")); resp.StatusCode != 403 {
		t.Errorf("a non-member answered %d, want 403", resp.StatusCode)
	}
}

func TestTheMetadataNamesTheResourceAClientFetchedItFor(t *testing.T) {
	for name, tc := range map[string]struct{ resource, want string }{
		"behind a proxy":  {"https://api.example.com", "https://api.example.com"},
		"served directly": {"", "http://desk:7373"},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://desk:7373"+goapiauth.ProtectedResourcePath, http.NoBody)
			rec := httptest.NewRecorder()
			goapiauth.ProtectedResourceMetadata{Resource: tc.resource, Issuer: "https://auth.example.com"}.ServeHTTP(rec, req)
			var doc struct {
				Resource string   `json:"resource"`
				Servers  []string `json:"authorization_servers"`
			}
			err := json.NewDecoder(rec.Body).Decode(&doc)
			if err != nil || doc.Resource != tc.want || len(doc.Servers) != 1 || doc.Servers[0] != "https://auth.example.com" {
				t.Errorf("the document = %+v, %v; want resource %s and the issuer", doc, err, tc.want)
			}
		})
	}
}
