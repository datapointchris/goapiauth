// Package publicpath decides which requests goapiauth's middleware passes with
// no credential.
package publicpath

import "slices"

// Metadata is where RFC 9728 puts an API's metadata, for an API served at the
// root of its host.
const Metadata = "/.well-known/oauth-protected-resource"

// Admits reports whether a request for path passes with no credential: it is
// Metadata, which a CLI reads before it holds a token, or one of public.
func Admits(path string, public []string) bool {
	return path == Metadata || slices.Contains(public, path)
}
