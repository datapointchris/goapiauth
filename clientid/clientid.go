// Package clientid spells the OAuth client ids a product registers with its
// identity provider: one for each person's machine and one for each service.
// It imports nothing, so a command-line client builds its own id from it
// without linking the verifier.
package clientid

// PersonPrefix starts the client id of every person's CLI for product:
// acme-cli-<host>.
func PersonPrefix(product string) string { return product + "-cli-" }

// ServicePrefix starts the client id of every service client for product:
// acme-svc-<name>.
func ServicePrefix(product string) string { return product + "-svc-" }
