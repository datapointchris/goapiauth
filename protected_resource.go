package goapiauth

import (
	"encoding/json"
	"net/http"
)

// ProtectedResourcePath is where RFC 9728 puts an API's metadata, for an API
// served at the root of its host. It is public: a CLI reads it before it holds
// a token, to learn which identity provider to log in through.
const ProtectedResourcePath = "/.well-known/oauth-protected-resource"

// protectedResourceMetadata is the RFC 9728 § 2 document, carrying only the
// two members a client needs to log in.
type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

// ProtectedResourceMetadata serves the RFC 9728 document naming issuer, the
// provider whose tokens the API accepts, for resource, the API's URL.
//
// A client refuses the document unless its resource equals the URL the client
// fetched it for (§ 3.3). An API behind a proxy that terminates TLS names its
// public URL as resource. An empty resource names the URL each request
// reached, for an API served directly under several names. That reads the
// scheme from the connection, so behind a TLS proxy it says http.
func ProtectedResourceMetadata(issuer, resource string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		named := resource
		if named == "" {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			named = scheme + "://" + r.Host
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protectedResourceMetadata{
			Resource:             named,
			AuthorizationServers: []string{issuer},
		})
	})
}
