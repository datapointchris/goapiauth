// Package refusal writes the body every request goapiauth turns away answers
// with.
package refusal

import (
	"encoding/json"
	"net/http"
)

// Write answers status with {"error": its status text, "message": message,
// "code": code}.
func Write(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": http.StatusText(status), "message": message, "code": code})
}

// Unauthorized answers 401 with the RFC 6750 Bearer challenge, naming
// bearerError in it where that is not empty, and the body Write gives it.
func Unauthorized(w http.ResponseWriter, bearerError, code, message string) {
	challenge := "Bearer"
	if bearerError != "" {
		challenge += ` error="` + bearerError + `"`
	}
	w.Header().Set("WWW-Authenticate", challenge)
	Write(w, http.StatusUnauthorized, code, message)
}
