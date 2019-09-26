// Package authentication_utils handles loading of signing key.
package authentication_utils

import (
	"crypto/rsa"
	"golang.org/x/crypto/pkcs12"
	"io/ioutil"
	"os"
)

// LoadSigningKey loads a RSA signing key out of a PKCS#12 container.
func LoadSigningKey(filePath, password string) (*rsa.PrivateKey, error) {

	// read the file content
	privateKeyData, err := readFile(filePath)
	if err != nil {
		return nil, err
	}

	// decode file content to privateKey
	privateKey, _, err := pkcs12.Decode(privateKeyData, password)
	if err != nil {
		return nil, err
	}

	return privateKey.(*rsa.PrivateKey), nil
}

// The readFile fetches the content of a file located on the
// given path
func readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return ioutil.ReadAll(file)
}
