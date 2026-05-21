package sdk

import (
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/pkg/errors"

	"github.com/0xkey-io/sdk-go/pkg/apikey"
)

// Authenticator provides a runtime.ClientAuthInfoWriter for use with the swagger API client.
type Authenticator struct {
	Key *apikey.Key
}

// AuthenticateRequest implements runtime.ClientAuthInfoWriter.
func (auth *Authenticator) AuthenticateRequest(req runtime.ClientRequest, _ strfmt.Registry) error {
	stamp, err := apikey.Stamp(req.GetBody(), auth.Key)
	if err != nil {
		return errors.Wrap(err, "failed to generate API stamp")
	}

	return req.SetHeaderParam("X-Stamp", stamp)
}
