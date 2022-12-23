package jcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	// ContentTypeJSON is the HTTP header value for Content-Type for JSON.
	ContentTypeJSON = "application/json"
	// HeaderContentType is the HTTP header for Content-Type.
	HeaderContentType = "Content-Type"
	logReqUUID        = "reqUUID"
)

// HTTPHandler is the HTTP handler for the Proxy.
type HTTPHandler struct {
	Logger          *zap.Logger
	Proxy           Proxy
	RequestMaxBytes int64
}

// Validate creates an HTTP handler for the associated Proxy method.
//
// If more HTTP handlers are added:
// * Use a middleware for HTTP request metadata method, content type, body limiting, etc.
func (h HTTPHandler) Validate() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx := request.Context()

		reqUUID, err := uuid.NewRandom()
		if err != nil {
			h.errorResponse(http.StatusInternalServerError, err, "Failed to generate UUID.", RequestMeta{}, writer)
			return
		}
		reqMeta := RequestMeta{
			UUID: reqUUID,
		}

		if request.Method != http.MethodPost {
			h.errorResponse(http.StatusMethodNotAllowed, err, "Incorrect HTTP method.", reqMeta, writer)
			return
		}

		contentType := request.Header.Get(HeaderContentType)
		if contentType != ContentTypeJSON {
			h.errorResponse(http.StatusBadRequest, err, fmt.Sprintf("Incorrect %s. Expected %s.", HeaderContentType, ContentTypeJSON), reqMeta, writer)
			return
		}

		readCloser := http.MaxBytesReader(writer, request.Body, h.RequestMaxBytes)
		//goland:noinspection GoUnhandledErrorResult
		defer readCloser.Close()

		body, err := io.ReadAll(readCloser)
		if err != nil {
			h.errorResponse(http.StatusRequestEntityTooLarge, nil, "Failed to read ", reqMeta, writer)
			return
		}

		var req ValidateRequest
		err = json.Unmarshal(body, &req)
		if err != nil {
			h.errorResponse(http.StatusBadRequest, nil, "", reqMeta, writer)
			return
		}

		results, err := h.Proxy.Validate(ctx, req.Args)
		if err != nil {
			var jwtErr *jwt.ValidationError
			if errors.As(err, &jwtErr) || errors.Is(err, ErrClaimCheck) {
				msg := fmt.Sprintf("Failed to validate token: %v.", err)
				h.errorResponse(http.StatusBadRequest, err, msg, reqMeta, writer)
				return
			}
			h.errorResponse(http.StatusInternalServerError, err, "Failed to perform verification.", reqMeta, writer)
			return
		}

		resp := ValidateResponse{
			Results: results,
			Meta:    reqMeta,
		}

		data, err := json.Marshal(resp)
		if err != nil {
			h.errorResponse(http.StatusInternalServerError, nil, "Failed to JSON marshal response.", reqMeta, writer)
			return
		}

		writer.Header().Set(HeaderContentType, ContentTypeJSON)
		_, err = writer.Write(data)
		if err != nil {
			h.errorResponse(http.StatusInternalServerError, nil, "Failed to write response.", reqMeta, writer)
			return
		}

		h.Logger.Info("Successfully verified token.", zap.String(logReqUUID, reqMeta.UUID.String()))
	})
}

func (h HTTPHandler) errorResponse(code int, err error, message string, meta RequestMeta, writer http.ResponseWriter) {
	h.Logger.Info("Sending error response.", zap.String(logReqUUID, meta.UUID.String()), zap.Int("code", code), zap.String("message", message), zap.Error(err))
	writer.Header().Set(HeaderContentType, ContentTypeJSON)
	writer.WriteHeader(code)
	data, err := json.Marshal(ErrorResponse{
		Code: code,
		Meta: meta,
		Msg:  message,
	})
	if err != nil {
		h.Logger.Error("Failed to JSON to encode error response.", zap.Error(err), zap.String(logReqUUID, meta.UUID.String()))
		data = []byte(fmt.Sprintf(`{"code":400,"meta":{"uuid":"%s"},"msg":"Failed to JSON to encode error response."}`, meta.UUID.String()))
	}
	_, err = writer.Write(data)
	if err != nil {
		h.Logger.Error("Failed to write error response.", zap.Error(err), zap.String(logReqUUID, meta.UUID.String()))
	}
}
