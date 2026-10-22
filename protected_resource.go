package goapiauth

import (
	"encoding/json"
	"net/http"

	"github.com/datapointchris/goapiauth/internal/publicpath"
)

// ProtectedResourcePath is where RFC 9728 puts an API's metadata, for an API
// served at the root of its host. It is public: a CLI reads it before it holds
// a token, to learn which identity provider to log in through.
const ProtectedResourcePath = publicpath.Metadata

// metadataDocument is the RFC 9728 § 2 document, carrying only the two
// members a client needs to log in.
type metadataDocument struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

// ProtectedResourceMetadata serves the RFC 9728 document a CLI reads to learn
// which provider to log in through. Both fields are URLs, so a call names each
// one: a transposed pair serves a document every client refuses.
type ProtectedResourceMetadata struct {
	// Resource is the API's URL. A client refuses the document unless it
	// equals the URL the client fetched it for (§ 3.3), so an API behind a
	// proxy that terminates TLS names its public URL here. Empty names the
	// URL each request reached, for an API served directly under several
	// names. That reads the scheme from the connection, so behind a TLS proxy
	// it says http.
	Resource string

	// Issuer is the provider whose tokens the API accepts.
	Issuer string
}

func (m ProtectedResourceMetadata) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	named := m.Resource
	if named == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		named = scheme + "://" + r.Host
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(metadataDocument{
		Resource:             named,
		AuthorizationServers: []string{m.Issuer},
	})
}
