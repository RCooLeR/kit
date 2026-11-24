// Package jsonhttp writes JSON responses and the error envelope the web clients parse:
//
//	{"error":{"code":"not_found","message":"not found"}}
//
// The code is the stable part a client switches on (@rcooler/http reads exactly this field); the
// message is for people reading a log or a network tab and must not carry internal detail. Which
// codes exist, and which status goes with which, is the service's API and stays there.
package jsonhttp

import (
	"encoding/json"
	"net/http"
)

// ContentType is sent with every response of this package. JSON is UTF-8 by definition, so the
// type carries no charset parameter.
const ContentType = "application/json"

// ErrorBody is the envelope of a failed request.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail names the failure.
type ErrorDetail struct {
	// Code is stable and machine-readable, in snake_case: "invalid_input", "not_found".
	Code string `json:"code"`
	// Message is a short human-readable text.
	Message string `json:"message"`
}

// WriteJSON sends value as JSON with the given status. The returned error is an encoding or
// connection failure after the status line went out: the response cannot be repaired, so the
// caller can only log it.
func WriteJSON(w http.ResponseWriter, status int, value any) error {
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(value)
}

// WriteError sends the error envelope with the given status, code and message.
func WriteError(w http.ResponseWriter, status int, code, message string) error {
	return WriteJSON(w, status, ErrorBody{Error: ErrorDetail{Code: code, Message: message}})
}
