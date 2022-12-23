package jcp

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/MicahParks/jsontype"
)

const (
	// DefaultRefreshInterval is the default time between refreshes of the JWKS.
	DefaultRefreshInterval = time.Hour
	// DefaultRefreshTimeout is the default time to wait for a refresh of the JWKS before cancelling and logging an
	// error.
	DefaultRefreshTimeout = 10 * time.Second
	// DefaultListenAddress is the default address to listen on.
	DefaultListenAddress = ":8080"
	// DefaultLogFormat is the default log format.
	DefaultLogFormat = LogFormatJSON
	// DefaultRequestMaxBytes is the default maximum number of bytes to read from a request.
	DefaultRequestMaxBytes = 1 << 20 // 1 MB as defined by http.DefaultMaxHeaderBytes.
)

// ErrInvalidConfig is returned when the configuration is invalid.
var ErrInvalidConfig = errors.New("invalid configuration")

const (
	// LogFormatJSON is the JSON log format.
	LogFormatJSON = "json"
	// LogFormatHuman is the human-readable log format.
	LogFormatHuman = "human"
)

// LogFormat is the set of enums for the format of logs.
type LogFormat string

// Config contains the configuration for the JWKS client proxy.
type Config struct {
	JWKS            map[string]JWKSConfig `json:"jwks"`
	ListenAddress   string                `json:"listenAddress"`
	LogFormat       string                `json:"logFormat"`
	RequestMaxBytes int64                 `json:"requestMaxBytes"`
}

// DefaultsAndValidate helps implement the jsontype.Config interface.
func (c Config) DefaultsAndValidate() (Config, error) {
	if len(c.JWKS) == 0 {
		return c, fmt.Errorf("%w: no JWKS provided", ErrInvalidConfig)
	}
	for k, v := range c.JWKS {
		u, err := url.Parse(k)
		if err != nil {
			return c, fmt.Errorf("failed to parse JWK Set URL: %q: %s: %w", k, err, ErrInvalidConfig)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return c, fmt.Errorf("invalid JWK Set URL scheme: %q: %w", u.Scheme, ErrInvalidConfig)
		}
		if c.JWKS[k].RefreshInterval.Get() == 0 {
			v.RefreshInterval = jsontype.New(DefaultRefreshInterval)
			c.JWKS[k] = v
		}
		if c.JWKS[k].RefreshTimeout.Get() == 0 {
			v.RefreshTimeout = jsontype.New(DefaultRefreshTimeout)
			c.JWKS[k] = v
		}
	}
	if c.ListenAddress == "" {
		c.ListenAddress = DefaultListenAddress
	}
	if c.LogFormat == "" {
		c.LogFormat = DefaultLogFormat
	} else {
		switch c.LogFormat {
		case LogFormatJSON, LogFormatHuman:
		default:
			return Config{}, fmt.Errorf("invalid log format: %q: %w", c.LogFormat, ErrInvalidConfig)
		}
	}
	if c.RequestMaxBytes == 0 {
		c.RequestMaxBytes = DefaultRequestMaxBytes
	}
	return c, nil
}

// JWKSConfig contains the configuration for a JWKS.
type JWKSConfig struct {
	RefreshInterval *jsontype.JSONType[time.Duration] `json:"refreshInterval"`
	RefreshTimeout  *jsontype.JSONType[time.Duration] `json:"refreshTimeout"`
}
