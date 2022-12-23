package jcp

import (
	"context"
	"errors"
	"fmt"

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
)

const (
	audClaim = "aud"
	issClaim = "iss"
	subClaim = "sub"
)

var (
	// ErrClaimCheck is returned when a registered claims check fails.
	ErrClaimCheck = errors.New("registered claims check failed")
	// ErrNoConfiguration is returned when no configuration is given.
	ErrNoConfiguration = errors.New("no configuration provided")
)

// Proxy is the interface for the JWKS client proxy.
type Proxy interface {
	Validate(ctx context.Context, args ValidateArgs) (ValidateResults, error)
}

type keyfuncer interface {
	Keyfunc(token *jwt.Token) (interface{}, error)
}

type proxy struct {
	keyfuncer keyfuncer
}

// NewProxy creates a new JWKS client proxy.
func NewProxy(multiple map[string]keyfunc.Options, options keyfunc.MultipleOptions) (Proxy, error) {
	if len(multiple) == 0 {
		return nil, fmt.Errorf("failed to create proxy, no remote JWK Set resources: %w", ErrNoConfiguration)
	}

	var k keyfuncer
	if len(multiple) == 1 {
		for u, opt := range multiple {
			jwks, err := keyfunc.Get(u, opt)
			if err != nil {
				return nil, fmt.Errorf("failed to get JWKS: %w", err)
			}
			k = jwks
			break
		}
	} else {
		m, err := keyfunc.GetMultiple(multiple, options)
		if err != nil {
			return nil, fmt.Errorf("failed to get JWKS: %w", err)
		}
		k = m
	}

	p := proxy{
		keyfuncer: k,
	}

	return p, nil
}

// Validate helps implement the Proxy interface.
func (p proxy) Validate(_ context.Context, args ValidateArgs) (ValidateResults, error) {
	claims := jwt.RegisteredClaims{}
	t, err := jwt.ParseWithClaims(args.Token, &claims, p.keyfuncer.Keyfunc)
	if err != nil || !t.Valid {
		return ValidateResults{}, fmt.Errorf("failed to parse token: %w", err)
	}
	const errMsg = "registered claim %q did not match any values in the required set: %w"
	if len(args.Aud) > 0 {
		ok := false
		for _, aud := range args.Aud {
			ok = claims.VerifyAudience(aud, true)
			if ok {
				break
			}
		}
		if !ok {
			return ValidateResults{}, fmt.Errorf(errMsg, audClaim, ErrClaimCheck)
		}
	}
	if len(args.Iss) > 0 {
		ok := false
		for _, iss := range args.Iss {
			ok = claims.Issuer == iss
			if ok {
				break
			}
		}
		if !ok {
			return ValidateResults{}, fmt.Errorf(errMsg, issClaim, ErrClaimCheck)
		}
	}
	if len(args.Sub) > 0 {
		ok := false
		for _, sub := range args.Sub {
			ok = claims.Subject == sub
			if ok {
				break
			}
		}
		if !ok {
			return ValidateResults{}, fmt.Errorf(errMsg, subClaim, ErrClaimCheck)
		}
	}
	return ValidateResults{}, nil
}
