package sdk

import (
	"fmt"

	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"

	"github.com/0xkey-io/sdk-go/pkg/api/client"
	"github.com/0xkey-io/sdk-go/pkg/apikey"
	"github.com/0xkey-io/sdk-go/pkg/store/local"
)

type config struct {
	apiKey          *apikey.Key
	clientVersion   string
	registry        strfmt.Registry
	transportConfig *client.TransportConfig
	logger          Logger
}

type defaultLogger struct{}

func (d *defaultLogger) Printf(format string, v ...interface{}) {
	fmt.Printf(format+"\n", v...)
}

// Logger defines a minimal logging interface.
// Compatible with stdlib log.Logger, zap.SugaredLogger, etc.
type Logger interface {
	Printf(format string, v ...interface{})
}

// OptionFunc defines a function which sets configuration options for a Client.
type OptionFunc func(c *config) error

// WithLogger sets a custom logger for the SDK.
func WithLogger(logger Logger) OptionFunc {
	return func(c *config) error {
		c.logger = logger
		return nil
	}
}

// WithClientVersion overrides the client version used for this API client.
func WithClientVersion(clientVersion string) OptionFunc {
	return func(c *config) error {
		c.clientVersion = clientVersion
		return nil
	}
}

// WithRegistry sets the registry formats used for this API client.
func WithRegistry(registry strfmt.Registry) OptionFunc {
	return func(c *config) error {
		c.registry = registry
		return nil
	}
}

// WithTransportConfig sets the TransportConfig used for this API client.
func WithTransportConfig(transportConfig client.TransportConfig) OptionFunc {
	return func(c *config) error {
		c.transportConfig = &transportConfig
		return nil
	}
}

// WithAPIKey sets the API key used for this API client.
func WithAPIKey(apiKey *apikey.Key) OptionFunc {
	return func(c *config) error {
		c.apiKey = apiKey
		return nil
	}
}

// WithAPIKeyName sets the API key loaded from the local keystore with the provided name.
func WithAPIKeyName(keyname string) OptionFunc {
	return func(c *config) error {
		apiKey, err := local.New[*apikey.Key]().Load(keyname)
		if err != nil {
			return errors.Wrap(err, "failed to load API key")
		}

		c.apiKey = apiKey
		return nil
	}
}
