package crypto_test

import (
	"github.com/mastercard/oauth1-signer-go/crypto"
	"github.com/mastercard/oauth1-signer-go/utils"
	"testing"
)

const (
	sha256Length = 32
	sha1Length = 20
)

func TestSHA256Hash(t *testing.T) {

	var input [10]byte
	sha256 := crypto.Sha256(input[:])

	if sha256Length != len(sha256) {
		t.Errorf("Expected len of sha256 hash %v, got %v", sha256Length, len(sha256))
	}
}

func TestRSASignature(t *testing.T) {

	privateKey, _ := utils.LoadSigningKey("../testdata/test_key_container.p12", "Password1")
	var signingData [10]byte
	sign, err := crypto.Sign(signingData[:], privateKey)

	if err != nil || sign == nil {
		t.Errorf("Expected to generate signature, but thrwon %v", err)
	}
}

func TestSHA1Hash(t *testing.T) {

	var input [10]byte
	sha1 := crypto.Sha1(input[:])

	if sha1Length != len(sha1) {
		t.Errorf("Expected len of sha256 hash %v, got %v", sha256Length, len(sha1))
	}
}

func TestRSASignatureSHA1(t *testing.T) {

	privateKey, _ := utils.LoadSigningKey("../testdata/test_key_container.p12", "Password1")
	var signingData [10]byte
	sign, err := crypto.SignSHA1(signingData[:], privateKey)

	if err != nil || sign == nil {
		t.Errorf("Expected to generate signature, but thrwon %v", err)
	}
}
