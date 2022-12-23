package jcp

import (
	"github.com/google/uuid"
)

// ErrorResponse is the response for an error.
type ErrorResponse struct {
	Code int         `json:"code"`
	Meta RequestMeta `json:"meta"`
	Msg  string      `json:"msg"`
}

// RequestMeta is the metadata for a request.
type RequestMeta struct {
	UUID uuid.UUID `json:"uuid"`
}

// ValidateArgs are the arguments for a verification request.
type ValidateArgs struct {
	Aud   []string `json:"aud"`
	Iss   []string `json:"iss"`
	Sub   []string `json:"sub"`
	Token string   `json:"token"`
}

// ValidateRequest is the request for a verification.
type ValidateRequest struct {
	Args ValidateArgs `json:"args"`
}

// ValidateResponse is the response for a verification.
type ValidateResponse struct {
	Results ValidateResults `json:"results"`
	Meta    RequestMeta     `json:"meta"`
}

// ValidateResults are the results of a verification.
type ValidateResults struct {
	Success bool `json:"success"`
}
