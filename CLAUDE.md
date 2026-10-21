# goapiauth — Claude Code instructions

A public Go library, not a server. There is no `main` package and nothing to
install; it ships as git tags. Its consumers are Go web APIs whose users log in
through an OIDC provider. `goclilogin` is the command-line client those users
log in with, and `gobrowserlogin` is the browser's login.

Written to be used by strangers. Treat the exported API, the README and the
godoc as the product. A change that suits the internal consumers is not
automatically right.

## Layout

| Path | Holds |
| --- | --- |
| `doc.go` | Package doc: what a token must be, and why the keys outlive an outage |
| `verifier.go` | `Config`, the prefixes, `Identity`, `Verifier`, and the held key set |
| `connecting.go` | `Connecting`: a verifier that starts before the provider answers |
| `bearer.go` | `RequireBearer`, `RequireGroup`, and the identity on the context |
| `services.go` | `LimitServices`: a service kept to the routes its scopes list |
| `protected_resource.go` | The RFC 9728 metadata a CLI logs in from |
| `internal/refusal/` | The one refusal body, and the bearer refusal codes |
| `tokenorsession/` | A bearer token or a gobrowserlogin session; the only importer of gobrowserlogin |
| `authtest/` | A stand-in provider for a consumer's tests |

## Constraints that must not regress

- **Held keys verify through an outage.** A failed re-read never discards
  them. `TestTheKeySetUnderForgedTokensAndAProviderOutage` is that case, and
  the one-read-per-gap case beside it.
- **An empty `ServicePrefix` refuses every service token.** Every string has
  the empty prefix, so an unguarded check reads every client as a service.
  `TestVerifyAcceptsOnlyThisAPIsClients` fails without the guard.
- **A bearer credential never falls through to a session.**
  `TestRequireAdmitsATokenOrASessionAndNeverPairsThem` fails if it does.
- **The client id decides person or service, never the presence of `sub`.**
- **Each dependency earns its place.** This is the credential path.
  - `github.com/go-jose/go-jose` parses and verifies the signed token.
  - `golang.org/x/sync` shares one key read among the requests waiting on it.
  - `github.com/datapointchris/gobrowserlogin` is imported by
    `tokenorsession` alone.

  The verifier reaches the network only to read the issuer's discovery
  document and its key set, on a client with a timeout of its own.

## Never write the breaking-change trailer in a commit message

Those two words anywhere in a message cut a major once this repo is past 0.x.
A major from v1 on, on a Go module with no `/vN` path, is an outage rather than
a version: consumers resolving `@latest` stop seeing the tag. On 0.x,
`allow-initial-development-versions` cuts them as a minor. The analyzer matches
unanchored, so a commit that merely *discusses* the trailer cuts one too — say
"that marker" instead.

This repo carries no `.semrelrc`. Reaching 1.0 is dropping
`allow-initial-development-versions`. A deliberate v2 needs a `.semrelrc`
mapping `chore(release-major)` to a major, and the same release adds `/v2` to
the module path.
