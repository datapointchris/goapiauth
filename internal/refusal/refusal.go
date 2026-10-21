// Package refusal writes the body every request goapiauth turns away answers
// with.
package refusal

import (
	"encoding/json"
	"net/http"
)

// The codes a bearer-token refusal carries beside its message, for a client
// that branches on why it was refused.
const (
	MissingToken                = "missing_token"
	InvalidToken                = "invalid_token"
	OutsideServiceScope         = "outside_service_scope"
	IdentityProviderUnavailable = "identity_provider_unavailable"
)

// Write answers status with {"error": its status text, "message": message},
// and code beside them where it is not empty.
func Write(w http.ResponseWriter, status int, code, message string) {
	body := map[string]string{"error": http.StatusText(status), "message": message}
	if code != "" {
		body["code"] = code
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
