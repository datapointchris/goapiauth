package goapiauth_test

import (
	"errors"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/datapointchris/goapiauth"
	"github.com/datapointchris/goapiauth/authtest"
)

func TestVerifyAcceptsOnlyThisAPIsClients(t *testing.T) {
	provider := authtest.NewProvider(t)
	verifier := provider.Verifier(t, "acme-cli-", "acme-svc-")
	service := map[string]any{"client_id": "acme-svc-scheduler", "scp": []string{"acme.report"}}
	with := func(base map[string]any, k string, v any) map[string]any {
		out := maps.Clone(base)
		out[k] = v
		return out
	}

	person, err := verifier.Verify(t.Context(), provider.Sign(t, "at+jwt", map[string]any{
		"client_id": "acme-cli-desk", "sub": "chris", "groups": []string{"admin"},
	}))
	if err != nil || person.Service || person.Subject != "chris" || !slices.Equal(person.Groups, []string{"admin"}) {
		t.Errorf("a person's token = %+v, %v; want chris in admin, not a service", person, err)
	}
	svc, err := verifier.Verify(t.Context(), provider.Sign(t, "at+jwt", service))
	if err != nil || !svc.Service || !slices.Equal(svc.Scopes, []string{"acme.report"}) {
		t.Errorf("a service's token = %+v, %v; want a service holding acme.report", svc, err)
	}

	for name, token := range map[string]string{
		"another product's CLI":   provider.Person(t, "other-cli-desk", "chris"),
		"an id token":             provider.Sign(t, "JWT", map[string]any{"client_id": "acme-cli-desk", "sub": "chris"}),
		"an expired token":        provider.Sign(t, "at+jwt", with(service, "exp", time.Now().Add(-time.Minute).Unix())),
		"another issuer":          provider.Sign(t, "at+jwt", with(service, "iss", "https://elsewhere.example")),
		"a service with no scope": provider.Sign(t, "at+jwt", with(service, "scp", []string{})),
		"a person with no sub":    provider.Sign(t, "at+jwt", map[string]any{"client_id": "acme-cli-desk"}),
	} {
		if _, err := verifier.Verify(t.Context(), token); !errors.Is(err, goapiauth.ErrUnauthorized) {
			t.Errorf("%s verified as %v, want ErrUnauthorized", name, err)
		}
	}

	// An API naming no service prefix must not read every client as one.
	personsOnly := provider.Verifier(t, "acme-cli-", "")
	if _, err := personsOnly.Verify(t.Context(), provider.Sign(t, "at+jwt", service)); !errors.Is(err, goapiauth.ErrUnauthorized) {
		t.Errorf("a service token sent to an API with no service prefix verified as %v, want ErrUnauthorized", err)
	}

	// A bare product name would admit acmecorp-cli-desk, so no verifier is built.
	if _, err := goapiauth.NewConnecting(goapiauth.Config{Issuer: "https://auth.example", PersonPrefix: "acme"}); err == nil {
		t.Error("a Config whose PersonPrefix is a bare product name was accepted")
	}
}
