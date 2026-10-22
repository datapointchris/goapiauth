// Package goapiauth authenticates requests to a Go web API whose users log in
// through an OIDC provider.
//
// A command-line client logs in with the device authorization grant, and a
// service with the client-credentials grant. Each then sends the provider's
// access token as a bearer token. Verifier checks it as an RFC 9068 JWT access
// token: signed by a key the provider publishes, typed at+jwt, from
// Config.Issuer, unexpired, and issued to one of this API's clients. The
// audience claim is not checked, because some providers leave it empty on a
// device grant's token. The client id's prefix is what keeps a token issued
// for another product out. Package clientid spells those prefixes.
//
// # The provider's keys
//
// The keys are read once and held. A token no held key verifies makes the
// Verifier read them again, which covers a key the provider has just rotated
// in. Those reads are at least 30 seconds apart, so a stream of forged tokens
// costs the provider one read per gap. Held keys older than five minutes are
// read again too, which bounds how long a key the provider stopped publishing
// still verifies. A token they verify is answered from them without waiting on
// that read, and when the read fails they go on verifying. An outage of the
// provider does not become an outage of the API, because a provider that
// cannot be read has not rotated its keys out.
//
// # Requests
//
// RequireBearer admits a request carrying a token the Verifier accepts, and
// puts the caller's Identity on the request's context, where IdentityFrom
// reads it. A refusal answers {"error": status text, "message": reason,
// "code": one of the Code constants}, and a client branches on the code.
// LimitServices keeps a service client to the routes its scopes list, and
// RequireGroup keeps a route to the members of one group.
//
// The tokenorsession package admits a bearer token or a gobrowserlogin
// session, for an API that serves its own browser front end. It alone imports
// gobrowserlogin.
//
// ProtectedResourceMetadata serves the RFC 9728 document a CLI reads to learn
// which provider to log in through. Both middlewares pass
// ProtectedResourcePath without a credential.
package goapiauth
