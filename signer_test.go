package oauth_test

import (
	"bytes"
	"encoding/json"
	oauth "github.com/mastercard/oauth1-signer-go"
	"github.com/mastercard/oauth1-signer-go/utils"
	"net/http"
	"testing"
)

const (
	consumerKey = "WFQHgP6gI01ZxbpqUzdWQ_GpDVrym3dhY6Q9X3PZe4ba3850!3b9f3d6593d04a0cbefadaf8bb3975fb0000000000000000"
)

var (
	signingKey, _ = utils.LoadSigningKey("testdata/test_key_container.p12", "Password1")
	jsonData      = map[string]string{"foo": "bår"}
	jsonValue, _  = json.Marshal(jsonData)
	request, _    = http.NewRequest("POST", "https://sandbox.api.mastercard.com/service", bytes.NewBuffer(jsonValue))
)

func TestHttpRequestSigning(t *testing.T) {
	signer := &oauth.Signer{
		ConsumerKey: consumerKey,
		SigningKey:  signingKey,
	}
	err := signer.Sign(request)
	if err != nil {
		t.Errorf("Expected to sign the http request, got %v", err)
	}

	authorizationVal := request.Header.Get(oauth.AuthorizationHeaderName)
	if len(authorizationVal) == 0 {
		t.Errorf("Expected the authorization header, got %v", authorizationVal)
	}
}

func TestHttpRequestSigningWithInvalidInput(t *testing.T) {

	// sign with nil consumer key and nil signing key
	signer := &oauth.Signer{}
	err := signer.Sign(request)
	if err == nil {
		t.Errorf("Expected to thrown an error in case of invalid signing data")
	}

	// sign with nil signing key
	signer = &oauth.Signer{ConsumerKey: consumerKey}
	err = signer.Sign(request)
	if err == nil {
		t.Errorf("Expected to thrown an error in case of invalid signing data")
	}

	// sign with nil http.Request
	signer = &oauth.Signer{ConsumerKey: consumerKey, SigningKey: signingKey}
	err = signer.Sign(nil)
	if err == nil {
		t.Errorf("Expected to thrown an error in case of Nil request")
	}

	// sign for http GET request
	getRequest, _ := http.NewRequest("GET", "https://sandbox.api.mastercard.com/service", nil)
	err = signer.Sign(getRequest)
	if err != nil {
		t.Errorf("Expected to sign http GET request, but got %v", err)
	}
	authorizationVal := getRequest.Header.Get(oauth.AuthorizationHeaderName)
	if len(authorizationVal) == 0 {
		t.Errorf("Expected the authorization header, got %v", authorizationVal)
	}

	// sign for http POST request
	err = signer.Sign(request)
	if err != nil {
		t.Errorf("Expected to sign http POST request, but got %v", err)
	}
	authorizationVal = request.Header.Get(oauth.AuthorizationHeaderName)
	if len(authorizationVal) == 0 {
		t.Errorf("Expected the authorization header, got %v", authorizationVal)
	}
}
