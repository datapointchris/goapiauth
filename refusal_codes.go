package goapiauth

// The code a refusal carries beside its error and message, for a client that
// branches on why it was refused. Every refusal goapiauth and tokenorsession
// write carries one of these.
const (
	// CodeMissingToken is a 401 for a request carrying no credential.
	CodeMissingToken = "missing_token"

	// CodeInvalidToken is a 401 for a bearer token the Verifier refused.
	CodeInvalidToken = "invalid_token"

	// CodeIdentityProviderUnavailable is a 503 for a token that could not be
	// checked, because the provider cannot be read and no held key verifies it.
	CodeIdentityProviderUnavailable = "identity_provider_unavailable"

	// CodeOutsideServiceScope is a 403 for a service client reaching a route
	// none of its scopes lists.
	CodeOutsideServiceScope = "outside_service_scope"

	// CodeOutsideGroup is a 403 for a caller outside the group RequireGroup
	// names.
	CodeOutsideGroup = "outside_group"

	// CodeMissingCSRFHeader is a 403 for a session cookie sent without
	// gobrowserlogin's CSRF header.
	CodeMissingCSRFHeader = "missing_csrf_header"

	// CodeSessionStoreUnavailable is a 503 for a session cookie whose session
	// could not be read.
	CodeSessionStoreUnavailable = "session_store_unavailable"
)
