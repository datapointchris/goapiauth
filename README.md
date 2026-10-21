# goapiauth

Authentication inside a Go web API whose users log in through an OIDC
provider. It verifies the provider's
[RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html) JWT access tokens, and
keeps verifying them while the provider is down. Its `tokenorsession` package
admits either a bearer token or a
[gobrowserlogin](https://github.com/datapointchris/gobrowserlogin) session, for
an API that serves its own browser front end.

The command-line half of the same login is
[goclilogin](https://github.com/datapointchris/goclilogin), which logs a CLI in
with the device authorization grant and sends the token this package checks.

## Install

```bash
go get github.com/datapointchris/goapiauth
```

## Starting from scratch

An API that only CLIs and services call:

```go
config := goapiauth.Config{
 Issuer:        "https://auth.example.com",
 PersonPrefix:  goapiauth.PersonPrefix("acme"),  // acme-cli-<host>
 ServicePrefix: goapiauth.ServicePrefix("acme"), // acme-svc-<name>
}
verifier := goapiauth.NewConnecting(config)
go verifier.Run(ctx, logger)

mux := http.NewServeMux()
mux.Handle("GET "+goapiauth.ProtectedResourcePath,
 goapiauth.ProtectedResourceMetadata(config.Issuer, "https://acme.example.com"))
mux.HandleFunc("GET /api/v1/reports", listReports)

routes := map[string][]string{"acme.read": {"GET /api/v1/reports"}}
handler := goapiauth.RequireBearer(verifier, logger, "/health")(
 goapiauth.LimitServices(mux, routes, logger))
```

An API that also serves a browser front end, which logs in through
gobrowserlogin:

```go
handler := tokenorsession.Require(verifier, sessions, logger,
 "/health", "/api/auth/login", "/api/auth/callback")(mux)
```

A handler reads who called with `goapiauth.IdentityFrom(r.Context())`.

## Which function answers which question

| Question | Answer |
| --- | --- |
| Is this token one of my clients', signed by my provider? | `Verifier.Verify` |
| Should the API start while the provider is down? | `NewConnecting`, and `Ready` for a readiness probe |
| Does this request carry an accepted token? | `RequireBearer` |
| Does it carry a token or a browser session? | `tokenorsession.Require` |
| Who called? | `IdentityFrom` |
| May this service reach this route? | `LimitServices` |
| Is this caller in a group? | `RequireGroup` |
| Where does a CLI learn which provider to log in through? | `ProtectedResourceMetadata` |

## `Verify` — the client id decides whose token it is

A token is refused unless it is signed with RS256 by a key the provider
publishes, typed `at+jwt`, from `Config.Issuer` and unexpired. The type check
keeps out an ID token, which carries the same signature and issuer and is
handed to the client. The provider leaves the audience claim empty on a device
grant's token, so the client id's prefix is what keeps a token issued for
another product out.

A token from a `PersonPrefix` client is a person's and must carry `sub`. One
from a `ServicePrefix` client is a service's and must carry a non-empty `scp`.
A missing `sub` cannot decide which a token is. The provider leaves it off a
client-credentials token, but RFC 9068 requires one, and a release that added
it would make a service look like a person. An empty `ServicePrefix` refuses
every service token.

## The keys outlive an outage

The keys are read at startup and held. Held keys older than five minutes are
read again on the next token, which bounds how long a key the provider stopped
publishing still verifies. When that read fails, a token the held keys verify
is accepted, because a provider that cannot be read has not rotated them out.
An API that dropped its keys at a fixed age would refuse every token a few
minutes into an outage, and every caller would see the API down with it.

A token naming a key the held set lacks makes the Verifier read the keys
again, which covers a key the provider has just rotated in. Those reads are at
least 30 seconds apart, so anyone able to reach the API cannot turn a stream of
forged tokens into a stream of reads.

## Refusals — one body, and a code to branch on

Every refusal answers `{"error": <status text>, "message": <reason>}`. The
reason names what is wrong with the request, never which check a token failed.
A bearer refusal adds a `code`:

| Status | `code` | When |
| --- | --- | --- |
| 401 | `missing_token` | no bearer token |
| 401 | `invalid_token` | a token the Verifier refused |
| 503 | `identity_provider_unavailable` | the provider cannot be read, and no held key verifies the token |
| 403 | `outside_service_scope` | a service outside its scopes |

A 401 carries the RFC 6750 `WWW-Authenticate: Bearer` challenge. In
`tokenorsession`, a request with no credential at all is a 401, a session
cookie without gobrowserlogin's CSRF header is a 403, and a session store that
cannot be read is a 503.

## `tokenorsession` — a token never falls through to a session

A request carrying a bearer token is judged on the token alone, and the
session is never consulted. Falling through would let a caller pair a junk
token with a stolen cookie. A request with no bearer token is judged on its
session, and its Identity carries the session's subject and groups.

## What it deliberately does not do

- **No token introspection.** A JWT access token verifies offline, and an
  introspection call per request would make the provider a dependency of every
  request.
- **No algorithm other than RS256.** A token naming another is refused before
  any key is tried.
- **No audience check.** The device grant leaves the claim empty. The client
  id prefix does that job.
