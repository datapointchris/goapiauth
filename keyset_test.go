package goapiauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestTheKeySetUnderForgedTokensAndAProviderOutage(t *testing.T) {
	issuerKey := rsaKey(t)
	var reads atomic.Int32
	var down, hang atomic.Bool
	release := make(chan struct{})
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch {
		case hang.Load():
			<-release
			return
		case down.Load():
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		reads.Add(1)
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &issuerKey.PublicKey, KeyID: "main", Algorithm: string(jose.RS256), Use: "sig"},
		}})
	}))
	t.Cleanup(provider.Close)
	t.Cleanup(func() { close(release) })

	keys := &keySet{uri: provider.URL, client: provider.Client()}
	start := time.Now()
	if _, err := keys.fetch(t.Context(), start); err != nil {
		t.Fatal(err)
	}
	valid := signedWith(t, issuerKey)
	forged := signedWith(t, rsaKey(t))

	t.Run("a stream of forged tokens reads the keys once per gap", func(t *testing.T) {
		before := reads.Load()
		for i := range 50 {
			at := start.Add(time.Second + time.Duration(i)*time.Millisecond)
			if _, err := keys.verify(t.Context(), forged, at); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("a forged token answered %v, want ErrUnauthorized", err)
			}
		}
		if got := reads.Load() - before; got != 1 {
			t.Errorf("50 forged tokens inside one gap read the keys %d times, want 1", got)
		}
	})

	t.Run("through a provider outage a held key's token verifies and any other meets the outage", func(t *testing.T) {
		down.Store(true)
		t.Cleanup(func() { down.Store(false) })
		long := start.Add(keySetLifespan + time.Hour)
		if _, err := keys.verify(t.Context(), valid, long); err != nil {
			t.Errorf("a valid token an hour into an outage answered %v, want it verified by the held keys", err)
		}
		// A token from a key rotated in before the outage looks like this one.
		// A 401 would send its caller to log in again, which cannot help.
		for _, at := range []time.Time{long.Add(time.Second), long.Add(keyRereadGap - time.Second)} {
			if _, err := keys.verify(t.Context(), forged, at); !errors.Is(err, ErrProviderUnavailable) {
				t.Errorf("a token no held key verifies, %s after the failed read, answered %v, want ErrProviderUnavailable", at.Sub(long), err)
			}
		}
	})

	t.Run("a provider that hangs holds back no token the held keys verify", func(t *testing.T) {
		hang.Store(true)
		later := start.Add(2*keySetLifespan + 2*time.Hour)
		began := time.Now()
		if _, err := keys.verify(t.Context(), valid, later); err != nil {
			t.Errorf("a valid token against a hanging provider answered %v, want it verified by the held keys", err)
		}
		if waited := time.Since(began); waited > time.Second {
			t.Errorf("a valid token waited %s on a provider that hangs, want an answer from the held keys at once", waited)
		}
	})
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signedWith(t *testing.T, key *rsa.PrivateKey) *jose.JSONWebSignature {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", "main"))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseAccessToken(compact)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
