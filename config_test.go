package jcp_test

import (
	"errors"
	"testing"

	"github.com/MicahParks/jsontype"

	"github.com/MicahParks/jcp"
)

const (
	validURL = "https://localhost"
)

func TestConfig_DefaultsAndValidate(t *testing.T) {
	validLogFormatExpected := createDefaultConfig()
	validLogFormatExpected.LogFormat = jcp.LogFormatHuman
	testCases := []struct {
		config   jcp.Config
		err      error
		expected jcp.Config
		name     string
	}{
		{
			config: jcp.Config{},
			err:    jcp.ErrInvalidConfig,
			name:   "Empty",
		},
		{
			config: jcp.Config{
				JWKS: map[string]jcp.JWKSConfig{
					validURL: {},
				},
			},
			expected: createDefaultConfig(),
			name:     "EmptyWithJWKS",
		},
		{
			config: jcp.Config{
				JWKS: map[string]jcp.JWKSConfig{
					":": {},
				},
			},
			err:  jcp.ErrInvalidConfig,
			name: "InvalidURL",
		},
		{
			config: jcp.Config{
				JWKS: map[string]jcp.JWKSConfig{
					"tcp://localhost": {},
				},
			},
			err:  jcp.ErrInvalidConfig,
			name: "InvalidURLScheme",
		},
		{
			config: jcp.Config{
				JWKS: map[string]jcp.JWKSConfig{
					validURL: {},
				},
				LogFormat: jcp.LogFormatHuman,
			},
			expected: validLogFormatExpected,
			name:     "ValidLogFormat.",
		},
		{
			config: jcp.Config{
				JWKS: map[string]jcp.JWKSConfig{
					validURL: {},
				},
				LogFormat: "invalid",
			},
			err:  jcp.ErrInvalidConfig,
			name: "InvalidLogFormat",
		},
	}
	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			actual, err := tc.config.DefaultsAndValidate()
			if err != nil || tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Errorf("Expected error %v, got %v.", tc.err, err)
				}
				return
			}
			if actual.ListenAddress != tc.expected.ListenAddress {
				t.Errorf("Expected listen address %s, got %s.", tc.expected.ListenAddress, actual.ListenAddress)
			}
			if actual.LogFormat != tc.expected.LogFormat {
				t.Errorf("Expected log format %s, got %s.", tc.expected.LogFormat, actual.LogFormat)
			}
			if actual.RequestMaxBytes != tc.expected.RequestMaxBytes {
				t.Errorf("Expected request max bytes %d, got %d.", tc.expected.RequestMaxBytes, actual.RequestMaxBytes)
			}
			if len(actual.JWKS) != len(tc.expected.JWKS) {
				t.Errorf("Expected %d JWKS, got %d.", len(tc.expected.JWKS), len(actual.JWKS))
			}
			for k, v := range actual.JWKS {
				if v.RefreshInterval.Get() != tc.expected.JWKS[k].RefreshInterval.Get() {
					t.Errorf("Expected refresh interval %v, got %v.", tc.expected.JWKS[k].RefreshInterval.Get(), v.RefreshInterval.Get())
				}
				if v.RefreshTimeout.Get() != tc.expected.JWKS[k].RefreshTimeout.Get() {
					t.Errorf("Expected refresh timeout %v, got %v.", tc.expected.JWKS[k].RefreshTimeout.Get(), v.RefreshTimeout.Get())
				}
			}
		})
	}
}

func createDefaultConfig() jcp.Config {
	return jcp.Config{
		JWKS: map[string]jcp.JWKSConfig{
			validURL: {
				RefreshInterval: jsontype.New(jcp.DefaultRefreshInterval),
				RefreshTimeout:  jsontype.New(jcp.DefaultRefreshTimeout),
			},
		},
		ListenAddress:   jcp.DefaultListenAddress,
		LogFormat:       jcp.DefaultLogFormat,
		RequestMaxBytes: jcp.DefaultRequestMaxBytes,
	}
}
