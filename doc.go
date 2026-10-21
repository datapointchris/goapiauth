// Package goapiauth authenticates requests to a Go web API whose users log in
// through an OIDC provider.
//
// A command-line client logs in with the device authorization grant, and a
// service with the client-credentials grant. Each then sends the provider's
// access token as a bearer token. Verifier checks it as an RFC 9068 JWT access
// token: signed by a key the provider publishes, typed at+jwt, from
// Config.Issuer, unexpired, and issued to one of this API's clients. The device
// grant leaves the audience claim empty, so the client id's prefix is what
// keeps a token issued for another product out. A person's CLI client is
// PersonPrefix(product) followed by its host, and a service client is
// ServicePrefix(product) followed by its name.
//
// # The provider's keys
//
// The keys are read once and held. A token naming a key the held set lacks
// makes the Verifier read them again, at most once every 30 seconds, so a
// stream of forged tokens costs the provider one read per gap. Held keys older
// than five minutes are read again on the next token too, which bounds how long
// a key the provider stopped publishing still verifies. That age is never a
// cutoff: when the read fails, a token the held keys verify is accepted. An
// outage of the provider does not become an outage of the API, because a
// provider that cannot be read has not rotated its keys out.
//
// # Requests
//
// RequireBearer admits a request carrying a token the Verifier accepts, and
// puts the caller's Identity on the request's context, where IdentityFrom
// reads it. A refusal answers {"error": status text, "message": reason}, with
// a code beside them a client can branch on: missing_token, invalid_token,
// identity_provider_unavailable or outside_service_scope. LimitServices keeps a
// service client to the routes its scopes list, and RequireGroup keeps a route
// to the members of one group.
//
// The tokenorsession package admits a bearer token or a gobrowserlogin
// session, for an API that serves its own browser front end. It alone imports
// gobrowserlogin.
//
// ProtectedResourceMetadata serves the RFC 9728 document a CLI reads to learn
// which provider to log in through. Both middlewares pass
// ProtectedResourcePath without a credential.
package goapiauth
