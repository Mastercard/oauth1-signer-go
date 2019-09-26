package crypto_test

import (
	"github.com/mastercard/oauth1-signer-go/authentication_utils"
	"github.com/mastercard/oauth1-signer-go/crypto"
	"testing"
)

const (
	sha256Length = 32
)

func TestSHA256Hash(t *testing.T) {

	var input [10]byte
	sha256 := crypto.Sha256(input[:])

	if sha256Length != len(sha256) {
		t.Errorf("Expected len of sha256 hash %v, got %v", sha256Length, len(sha256))
	}
}

func TestRSASignature(t *testing.T) {

	privateKey, _ := authentication_utils.LoadSigningKey("../testdata/test_key_container.p12", "Password1")
	var signingData [10]byte
	sign, err := crypto.Sign(signingData[:], privateKey)

	if err != nil || sign == nil {
		t.Errorf("Expected to generate signature, but thrwon %v", err)
	}
}
