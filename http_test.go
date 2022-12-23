package jcp_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"

	"github.com/MicahParks/jcp"
)

var privateKey, jwksServer = createJWKSServer()

func createJWKSServer() (ed25519.PrivateKey, *httptest.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	j := jwkset.NewMemory[any]()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate key pair: %v.", err)
	}
	meta := jwkset.NewKey[any](public, testKID)
	err = j.Store.WriteKey(ctx, meta)
	if err != nil {
		log.Fatalf("Failed to store key: %v.", err)
	}
	rawJWKS, err := j.JSONPublic(ctx)
	if err != nil {
		log.Fatalf("Failed to get JWKS: %v.", err)
	}
	js := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err = w.Write(rawJWKS)
		if err != nil {
			log.Fatalf("Failed to write JWKS: %v.", err)
		}
	}))
	return private, js
}

func TestProxy(t *testing.T) {
	multiple := map[string]keyfunc.Options{
		jwksServer.URL: {},
	}
	proxy, err := jcp.NewProxy(multiple, keyfunc.MultipleOptions{})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v.", err)
	}

	handler := jcp.HTTPHandler{
		Logger:          zap.NewNop(),
		Proxy:           proxy,
		RequestMaxBytes: jcp.DefaultRequestMaxBytes,
	}.Validate()

	j := jwt.New(jwt.SigningMethodEdDSA)
	j.Header[headerKID] = testKID
	goodJWT, err := j.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign token: %v.", err)
	}

	testCases := []struct {
		args         *jcp.ValidateArgs
		contentType  string
		method       string
		name         string
		rawBody      io.Reader
		responseCode int
	}{
		{
			method:       http.MethodGet,
			name:         "MethodNotAllowed",
			responseCode: http.StatusMethodNotAllowed,
		},
		{
			contentType:  anyOtherString,
			name:         "ContentType",
			responseCode: http.StatusBadRequest,
		},
		{
			name:         "TooLarge",
			rawBody:      bytes.NewReader(make([]byte, jcp.DefaultRequestMaxBytes+1)),
			responseCode: http.StatusRequestEntityTooLarge,
		},
		{
			name:         "InvalidJSON",
			rawBody:      bytes.NewReader([]byte(anyOtherString)),
			responseCode: http.StatusBadRequest,
		},
		{
			args: &jcp.ValidateArgs{
				Token: anyOtherString,
			},
			name:         "NonJWT",
			responseCode: http.StatusBadRequest,
		},
		{
			args: &jcp.ValidateArgs{
				Token: goodJWT,
			},
			name: "GoodJWT",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			if tc.method == "" {
				tc.method = http.MethodPost
			}
			if tc.args != nil {
				req := jcp.ValidateRequest{
					Args: *tc.args,
				}
				b, err := json.Marshal(req)
				if err != nil {
					t.Fatalf("Failed to marshal args: %v.", err)
				}
				tc.rawBody = bytes.NewReader(b)
			}
			r := httptest.NewRequest(tc.method, jwksServer.URL, tc.rawBody)
			if tc.contentType == "" {
				tc.contentType = jcp.ContentTypeJSON
			}
			r.Header.Set(jcp.HeaderContentType, tc.contentType)
			handler.ServeHTTP(w, r)
			if tc.responseCode == 0 {
				tc.responseCode = http.StatusOK
			}
			if w.Code != tc.responseCode {
				t.Fatalf("Expected response code %d, but got %d.", tc.responseCode, w.Code)
			}
		})
	}
}
