package sdk

import (
	"bytes"
	"io"
	"net/http"
)

type roundTripperMiddleware func(http.RoundTripper) http.RoundTripper

func buildMiddlewareChain(base http.RoundTripper, logger Logger, clientVersion string) http.RoundTripper {
	middlewares := []roundTripperMiddleware{
		errorLoggingMiddleware(logger),
		clientVersionMiddleware(clientVersion),
	}

	chain := base
	for i := len(middlewares) - 1; i >= 0; i-- {
		chain = middlewares[i](chain)
	}

	return chain
}

func errorLoggingMiddleware(logger Logger) roundTripperMiddleware {
	return func(next http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			resp, err := next.RoundTrip(req)
			if err != nil {
				logger.Printf("Request failed: %v", err)
				return nil, err
			}

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				body, readErr := io.ReadAll(resp.Body)
				if readErr != nil {
					logger.Printf("Failed to read response body: %v", readErr)
					return resp, nil
				}

				logger.Printf("0xkey API response: %s", string(body))
				resp.Body = io.NopCloser(bytes.NewBuffer(body))
			}

			return resp, nil
		})
	}
}

func clientVersionMiddleware(clientVersion string) roundTripperMiddleware {
	return func(next http.RoundTripper) http.RoundTripper {
		return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			req.Header.Set("X-Client-Version", clientVersion)
			return next.RoundTrip(req)
		})
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

// SetClientVersion wraps inner with a RoundTripper that sets X-Client-Version.
func SetClientVersion(inner http.RoundTripper, clientVersion string) http.RoundTripper {
	return clientVersionMiddleware(clientVersion)(inner)
}
