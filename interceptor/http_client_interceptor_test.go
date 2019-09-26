package interceptor_test

import (
	"github.com/mastercard/oauth1-signer-go/interceptor"
	"net/http"
	"testing"
)

const (
	path        = "../testdata/test_key_container.p12"
	password    = "Password1"
	consumerKey = "WFQHgP6gI01ZxbpqUzdWQ_GpDVrym3dhY6Q9X3PZe4ba3850!3b9f3d6593d04a0cbefadaf8bb3975fb0000000000000000"
)

func TestHttpClientInterceptor(t *testing.T) {

	client, e := interceptor.GetHttpClient(consumerKey, path, password)
	if e != nil || client == nil {
		t.Errorf("Expected http.Client, but got %v", e)
	}
}

func TestHttpClientInterceptorInvalidInput(t *testing.T) {

	_, e := interceptor.GetHttpClient(consumerKey, path, "")
	if e == nil {
		t.Errorf("Expected an error to be thrown in case of invalid signing key input")
	}
}

func TestRoundTripWithInvalidInput(t *testing.T) {

	httpClient, e := interceptor.GetHttpClient("", path, password)
	if e != nil {
		t.Errorf("Expected valid http client, but got %v", e)
	}

	request, _ := http.NewRequest("GET", "https://sandbox.api.mastercard.com/service", nil)
	_, e = httpClient.Do(request)
	if e == nil {
		t.Errorf("Expected an error to be thrown in case of invalid consumer key")
	}
}
