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
 PersonPrefix:  clientid.PersonPrefix("acme"),  // acme-cli-<host>
 ServicePrefix: clientid.ServicePrefix("acme"), // acme-svc-<name>
}
verifier, err := goapiauth.NewConnecting(config)
if err != nil {
 return err
}
go verifier.Run(ctx, logger)

mux := http.NewServeMux()
mux.Handle("GET "+goapiauth.ProtectedResourcePath, goapiauth.ProtectedResourceMetadata{
 Resource: "https://acme.example.com",
 Issuer:   config.Issuer,
})
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
| What client id does a product's CLI or service register? | `clientid.PersonPrefix`, `clientid.ServicePrefix` |

## `Verify` — the client id decides whose token it is

A token is refused unless it is signed with RS256 by a key the provider
publishes, typed `at+jwt`, from `Config.Issuer` and unexpired. The type check
keeps out an ID token, which carries the same signature and issuer and is
handed to the client. The audience claim is not checked, because some
providers leave it empty on a device grant's token. The client id's prefix is
what keeps a token issued for another product out, so `Config` refuses a
prefix `clientid` could not have built.

A token from a `PersonPrefix` client is a person's and must carry `sub`. One
from a `ServicePrefix` client is a service's and must carry a non-empty `scp`.
A missing `sub` cannot decide which a token is. Some providers leave it off a
client-credentials token, but RFC 9068 requires one, and a release that added
it would make a service look like a person. An empty `ServicePrefix` refuses
every service token.

## The keys outlive an outage

The keys are read at startup and held. Held keys past an age the package doc
gives are read again, which bounds how long a key the provider stopped
publishing still verifies. A token they verify is answered without waiting on
that read. When the read fails they go on verifying, because a provider that
cannot be read has not rotated them out. An API that dropped its keys at a
fixed age would refuse every token a few minutes into an outage, and every
caller would see the API down with it.

A token no held key verifies makes the Verifier read the keys again, which
covers a key the provider has just rotated in. Those reads are spaced by a
minimum gap, so anyone able to reach the API cannot turn a stream of forged
tokens into a stream of reads. Inside the gap after a failed read, such a
token is refused as the outage it met, never as a bad token.

## Refusals — one body, and a code to branch on

Every refusal answers `{"error": <status text>, "message": <reason>, "code":
<code>}`. The reason names what is wrong with the request, never which check a
token failed. The codes are exported as the `Code` constants:

| Status | `code` | When |
| --- | --- | --- |
| 401 | `missing_token` | no credential |
| 401 | `invalid_token` | a token the Verifier refused |
| 503 | `identity_provider_unavailable` | the provider cannot be read, and no held key verifies the token |
| 403 | `outside_service_scope` | a service outside its scopes |
| 403 | `outside_group` | a caller outside the group `RequireGroup` names |
| 403 | `missing_csrf_header` | a session cookie without gobrowserlogin's CSRF header |
| 503 | `session_store_unavailable` | a session that cannot be read |

A 401 carries the RFC 6750 `WWW-Authenticate: Bearer` challenge.

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
- **No audience check.** Some providers leave the claim empty on a device
  grant's token. The client id prefix does that job.
