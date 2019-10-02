package utils_test

import (
	"github.com/mastercard/oauth1-signer-go/utils"
	"testing"
)

func TestLoadSigningKey(t *testing.T) {

	path := "../testdata/test_key_container.p12"
	password := "Password1"
	privateKey, err := utils.LoadSigningKey(path, password)

	if err != nil || privateKey == nil {
		t.Errorf("Expected to load RSA privateKey, but thrwon %v", err)
	}
}

func TestLoadSigningKeyInvalidInput(t *testing.T) {

	privateKey, err := utils.LoadSigningKey(
		"../testdata/invalidFile.p12", "Password1")

	if err == nil || privateKey != nil {
		t.Errorf("Expected to throw error, but returned privateKey")
	}

	privateKey, err = utils.LoadSigningKey(
		"../testdata/test_key_container.p12", "incorrect_password")

	if err == nil || privateKey != nil {
		t.Errorf("Expected to throw error in case of incorrect password")
	}
}
