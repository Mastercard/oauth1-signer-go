// Package interceptor handles oauth signing of every http request before
// sending.
package interceptor

import (
	"github.com/mastercard/oauth1-signer-go"
	"github.com/mastercard/oauth1-signer-go/authentication_utils"
	"net/http"
)

// The httpClientInterceptor is the composition of http.RoundTripper and oauth.Signer
// Every http call can be intercepted through http.RoundTripper and
// oauth.Signer is used to sign the http request and generate oauth1.0a
// authentication header
type httpClientInterceptor struct {
	http.RoundTripper
	oauth.Signer
}

// RoundTrip intercepts every http call and signs the http request
// before making an actual call
func (h *httpClientInterceptor) RoundTrip(req *http.Request) (*http.Response, error) {
	err := h.Signer.Sign(req)
	if err != nil {
		return nil, err
	}
	return h.RoundTripper.RoundTrip(req)
}

// GetHttpClient provides the http.Client having capability to intercept
// the http call and add the generated oauth1.0a header in each request.
// consumerKey: provide the consumer key received from mastercard developer portal
// filePath: a file path of a RSA private key in PKCS#12 format
// password: a password to read the RSA private key from the given file path
func GetHttpClient(consumerKey, filePath, password string) (*http.Client, error) {
	signingKey, e := authentication_utils.LoadSigningKey(filePath, password)
	if e != nil {
		return nil, e
	}
	signer := oauth.Signer{ConsumerKey: consumerKey, SigningKey: signingKey}

	return &http.Client{
		Transport: &httpClientInterceptor{
			http.DefaultTransport,
			signer,
		},
	}, nil
}
