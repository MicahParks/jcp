package main

import (
	"log"
	"net/http"

	"github.com/MicahParks/jsontype"
	"github.com/MicahParks/keyfunc"
	"go.uber.org/zap"

	"github.com/MicahParks/jcp"
)

func main() {
	config, err := jsontype.Read[jcp.Config]()
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}

	var l *zap.Logger
	switch config.LogFormat {
	case jcp.LogFormatHuman:
		l, err = zap.NewDevelopment()
	case jcp.LogFormatJSON:
		l, err = zap.NewProduction()
	default:
		log.Fatalf("Unknown log format: %s. Configuration should have stopped this.", config.LogFormat)
	}
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	//goland:noinspection GoUnhandledErrorResult
	defer l.Sync()

	l.Info("Configuration read and validated.")

	multiple := make(map[string]keyfunc.Options, len(config.JWKS))
	for u, jwks := range config.JWKS {
		multiple[u] = keyfunc.Options{
			RefreshInterval: jwks.RefreshInterval.Get(),
			RefreshTimeout:  jwks.RefreshTimeout.Get(),
		}
	}

	proxy, err := jcp.NewProxy(multiple, keyfunc.MultipleOptions{})
	if err != nil {
		l.Fatal("Failed to create proxy.", zap.Error(err))
	}

	handler := jcp.HTTPHandler{
		Logger:          l,
		Proxy:           proxy,
		RequestMaxBytes: config.RequestMaxBytes,
	}

	http.Handle("/v1/validate", handler.Validate())

	err = http.ListenAndServe(config.ListenAddress, nil)
	if err != nil {
		l.Fatal("Failed to listen and serve.", zap.Error(err))
	}
}
