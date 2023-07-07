package oauth

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"net/http"
)

// Signer represents the http request signer that holds the
// consumer key and the signing key.
type Signer struct {
	ConsumerKey string
	SigningKey  *rsa.PrivateKey
}

// Sign signs the http request. It generates the authorization header and sets
// on the header of provided http request.
func (signer *Signer) Sign(req *http.Request) error {
	if signer.ConsumerKey == "" {
		return errors.New("signer: provide valid consumer key")
	}
	if signer.SigningKey == nil {
		return errors.New("signer: provide valid signing key")
	}
	if req == nil {
		return errors.New("signer: Nil http.Request provided")
	}
	body, err := getRequestBody(req)
	if err != nil {
		return err
	}
	authHeader, err := GetAuthorizationHeader(req.URL, req.Method, body, signer.ConsumerKey, signer.SigningKey)
	if err != nil {
		return err
	}
	req.Header.Set(AuthorizationHeaderName, authHeader)
	return nil
}

// The getRequestBody extracts the body content from the given
// http request and returns in []byte format.
func getRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	getBody, e := req.GetBody()
	if e != nil {
		return nil, e
	}
	defer func() { _ = getBody.Close() }()

	return ioutil.ReadAll(getBody)
}
