// Package sdk provides a Go SDK with which to interact with the 0xkey API service.
package sdk

import (
	_ "embed"
	"strings"

	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/0xkey-io/sdk-go/pkg/api/client"
	"github.com/0xkey-io/sdk-go/pkg/apikey"
)

//go:embed VERSION
var embeddedVersion string

// DefaultClientVersion is sent as the X-Client-Version header on API requests.
var DefaultClientVersion = "0xkey-go/" + strings.TrimSpace(embeddedVersion)

// Client provides a handle by which to interact with the 0xkey API.
type Client struct {
	Client        *client.ZeroXKeyAPI
	Authenticator *Authenticator
	APIKey        *apikey.Key
}

// New returns a new API Client with the given options.
func New(options ...OptionFunc) (*Client, error) {
	cfg := &config{
		clientVersion:   DefaultClientVersion,
		transportConfig: client.DefaultTransportConfig(),
	}

	for _, option := range options {
		if err := option(cfg); err != nil {
			return nil, err
		}
	}

	if cfg.logger == nil {
		cfg.logger = &defaultLogger{}
	}

	transport := httptransport.New(
		cfg.transportConfig.Host,
		cfg.transportConfig.BasePath,
		cfg.transportConfig.Schemes,
	)
	transport.Transport = buildMiddlewareChain(transport.Transport, cfg.logger, cfg.clientVersion)

	return &Client{
		Client:        client.New(transport, cfg.registry),
		Authenticator: &Authenticator{Key: cfg.apiKey},
		APIKey:        cfg.apiKey,
	}, nil
}

// NewHTTPClient returns a new base HTTP API client.
// Deprecated: Use New(WithRegistry(formats)) instead.
func NewHTTPClient(formats strfmt.Registry) *client.ZeroXKeyAPI {
	return client.NewHTTPClient(formats)
}

// DefaultOrganization returns the first organization found in the APIKey's set of organizations.
func (c *Client) DefaultOrganization() *string {
	for _, org := range c.APIKey.Organizations {
		return &org
	}

	return nil
}

// V0 returns the raw initial 0xkey API client.
func (c *Client) V0() *client.ZeroXKeyAPI {
	return c.Client
}
