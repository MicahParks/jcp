package jcp_test

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"

	"github.com/MicahParks/jcp"
)

const (
	anyNonEmptyString = "Any non-empty string."
	anyOtherString    = "Any other string."
	audClaim          = "aud"
	headerKID         = "kid"
	testKID           = "my-key-id"
)

func TestNewProxy(t *testing.T) {
	var urlErr *url.Error
	testCases := []struct {
		err      error
		errAs    any
		multiple map[string]keyfunc.Options
		name     string
		options  keyfunc.MultipleOptions
	}{
		{
			err:  jcp.ErrNoConfiguration,
			name: "Empty",
		},
		{
			multiple: map[string]keyfunc.Options{
				jwksServer.URL: {},
			},
			name: "Single",
		},
		{
			multiple: map[string]keyfunc.Options{
				"": {},
			},
			errAs: urlErr,
			name:  "SingleBadURL",
		},
		{
			multiple: map[string]keyfunc.Options{
				jwksServer.URL:               {},
				jwksServer.URL + "/anything": {},
			},
			name: "Multiple",
		},
		{
			multiple: map[string]keyfunc.Options{
				jwksServer.URL: {},
				"":             {},
			},
			errAs: urlErr,
			name:  "MultipleBadURL",
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			proxy, err := jcp.NewProxy(tc.multiple, tc.options)
			if err != nil || tc.err != nil || tc.errAs != nil {
				if errors.Is(err, tc.err) {
					return
				}
				if tc.errAs != nil && errors.As(err, &tc.errAs) {
					return
				}
				t.Fatalf("Expected error %v, got error %v.", tc.err, err)
			}
			if proxy == nil {
				t.Fatal("Expected proxy, got nil.")
			}
		})
	}
}

func TestProxy_Validate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	multiple := map[string]keyfunc.Options{
		jwksServer.URL: {},
	}
	proxy, err := jcp.NewProxy(multiple, keyfunc.MultipleOptions{})
	if err != nil {
		t.Fatalf("Failed to create proxy: %v.", err)
	}

	j := jwt.New(jwt.SigningMethodEdDSA)
	j.Header[headerKID] = testKID
	noClaims, err := j.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign goodAud token: %v.", err)
	}

	claims := jwt.RegisteredClaims{
		Audience: jwt.ClaimStrings{anyNonEmptyString},
	}
	j = jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	j.Header[headerKID] = testKID
	goodAud, err := j.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign goodAud token: %v.", err)
	}

	claims.Audience = jwt.ClaimStrings{anyOtherString}
	j = jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	j.Header[headerKID] = testKID
	badAud, err := j.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign badAud token: %v.", err)
	}

	claims.Issuer = anyNonEmptyString
	j = jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	j.Header[headerKID] = testKID
	goodIss, err := j.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign goodIss token: %v.", err)
	}

	claims.Issuer = anyOtherString
	j = jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	j.Header[headerKID] = testKID
	badIss, err := j.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign badIss token: %v.", err)
	}

	claims.Subject = anyNonEmptyString
	j = jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	j.Header[headerKID] = testKID
	goodSub, err := j.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign goodSub token: %v.", err)
	}

	claims.Subject = anyOtherString
	j = jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	j.Header[headerKID] = testKID
	badSub, err := j.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign badSub token: %v.", err)
	}

	testCases := []struct {
		args    jcp.ValidateArgs
		err     error
		name    string
		results jcp.ValidateResults
	}{
		{
			err:  jwt.ErrTokenMalformed,
			name: "Empty",
		},
		{
			args: jcp.ValidateArgs{
				Token: noClaims,
			},
			name: "Valid",
		},
		{
			args: jcp.ValidateArgs{
				Aud:   []string{anyNonEmptyString},
				Token: noClaims,
			},
			err:  jcp.ErrClaimCheck,
			name: "Aud",
		},
		{
			args: jcp.ValidateArgs{
				Iss:   []string{anyNonEmptyString},
				Token: noClaims,
			},
			err:  jcp.ErrClaimCheck,
			name: "Iss",
		},
		{
			args: jcp.ValidateArgs{
				Sub:   []string{anyNonEmptyString},
				Token: noClaims,
			},
			err:  jcp.ErrClaimCheck,
			name: "Sub",
		},
		{
			args: jcp.ValidateArgs{
				Aud:   []string{anyNonEmptyString},
				Token: goodAud,
			},
			name: "GoodAud",
		},
		{
			args: jcp.ValidateArgs{
				Aud:   []string{anyNonEmptyString},
				Token: badAud,
			},
			err:  jcp.ErrClaimCheck,
			name: "BadAud",
		},
		{
			args: jcp.ValidateArgs{
				Iss:   []string{anyNonEmptyString},
				Token: goodIss,
			},
			name: "GoodIss",
		},
		{
			args: jcp.ValidateArgs{
				Iss:   []string{anyNonEmptyString},
				Token: badIss,
			},
			err:  jcp.ErrClaimCheck,
			name: "BadIss",
		},
		{
			args: jcp.ValidateArgs{
				Sub:   []string{anyNonEmptyString},
				Token: goodSub,
			},
			name: "GoodSub",
		},
		{
			args: jcp.ValidateArgs{
				Sub:   []string{anyNonEmptyString},
				Token: badSub,
			},
			err:  jcp.ErrClaimCheck,
			name: "BadSub",
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			results, err := proxy.Validate(ctx, tc.args)
			if err != nil || tc.err != nil {
				if errors.Is(err, tc.err) {
					return
				}
				t.Fatalf("Expected error %v, got error %v.", tc.err, err)
			}
			if results != tc.results {
				t.Fatalf("Expected results %v, got results %v.", tc.results, results)
			}
		})
	}
}
