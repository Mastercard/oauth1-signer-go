// Package oauth performs OAuth1.0a compliant signing with
// body hash support for non-urlencoded content types.
package oauth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/mastercard/oauth1-signer-go/crypto"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	AuthorizationHeaderName   = "Authorization"
	nonceLength               = 16
	alphaNumericChars         = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	authorizationPrefix       = "OAuth " // trailing space is required
	oauthConsumerKeyParam     = "oauth_consumer_key"
	oauthNonceParam           = "oauth_nonce"
	oauthSignatureParam       = "oauth_signature"
	oauthSignatureMethodParam = "oauth_signature_method"
	oauthTimestampParam       = "oauth_timestamp"
	oauthVersionParam         = "oauth_version"
	oauthBodyHashParam        = "oauth_body_hash"
	defaultOauthVersion       = "1.0"
	sha256HashingAlgorithm    = "SHA256"
)

// GetAuthorizationHeader creates a Mastercard API compliant OAuth Authorization header.
func GetAuthorizationHeader(u *url.URL, method string, payload []byte, consumerKey string, signingKey *rsa.PrivateKey) (string, error) {
	queryParams := extractQueryParams(u)

	// get all required oauth params
	oauthParams := getOAuthParams(consumerKey, payload)

	// combine query and oauth parameters into lexicographically sorted string
	paramString := toOauthParamString(queryParams, oauthParams)

	// normalized URL without query params and fragment
	baseUrl := getBaseUrlString(u)

	// signature base string
	sbs := getSignatureBaseString(method, baseUrl, paramString)

	// signature
	signature, err := signSignatureBaseString(sbs, signingKey)
	if err != nil {
		return "", err
	}
	oauthParams[oauthSignatureParam] = percentEncode(signature)

	return getAuthorizationString(oauthParams), nil
}

// The extractQueryParams parses query parameters out of the URL.
func extractQueryParams(u *url.URL) map[string][]string {
	queryParams := u.Query()
	rawQuery := u.RawQuery
	decodedQuery, _ := url.QueryUnescape(rawQuery)

	// whether to perform percent encode or not
	mustEncode := decodedQuery != rawQuery

	for k, v := range queryParams {
		// encode key
		if mustEncode {
			// encoded key is now need to be
			// inserted. Hence, remove the record
			// of original key
			queryParams.Del(k)
			k = percentEncode(k)
		}
		// encode value(s)
		for i, each := range v {
			if mustEncode {
				v[i] = percentEncode(each)
			} else {
				v[i] = each
			}
		}
		queryParams[k] = v
	}
	return queryParams
}

// The getOAuthParams returns map of oauth parameters.
func getOAuthParams(consumerKey string, payload []byte) map[string]string {
	params := map[string]string{
		oauthConsumerKeyParam:     consumerKey,
		oauthNonceParam:           getNonce(),
		oauthSignatureMethodParam: "RSA-" + sha256HashingAlgorithm,
		oauthTimestampParam:       getTimestamp(),
		oauthVersionParam:         defaultOauthVersion,
		oauthBodyHashParam:        getBodyHash(payload),
	}
	return params
}

// The getTimestamp returns UNIX timestamp
func getTimestamp() string {
	return strconv.FormatInt(epoch(), 10)
}

func epoch() int64 {
	return time.Now().Unix()
}

// The getBodyHash generates the hash of request payload
func getBodyHash(payload []byte) string {
	hash := crypto.Sha256(payload)
	return base64.StdEncoding.EncodeToString(hash)
}

// The getNonce generates a random string for replay protection as per
// https://tools.ietf.org/html/rfc5849#section-3.3
func getNonce() (nonce string) {
	randomVal := make([]byte, nonceLength)
	_, _ = rand.Read(randomVal)

	var length = len(alphaNumericChars)
	for _, v := range randomVal {
		nonce += string(alphaNumericChars[int(v)%length])
	}
	return
}

// The toOauthParamString sorts lexicographically all parameters and
// concatenate them into a string as per https://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
func toOauthParamString(queryParams map[string][]string, oauthParams map[string]string) string {
	consolidatedParams := make(map[string][]string, len(queryParams))
	for k, v := range queryParams {
		consolidatedParams[k] = v
	}

	// Add OAuth params to consolidated params map
	for k, v := range oauthParams {
		if val, ok := consolidatedParams[k]; ok {
			consolidatedParams[k] = append(val, v)
		} else {
			consolidatedParams[k] = []string{v}
		}
	}

	// sort as per the keys
	keys := make([]string, len(consolidatedParams))
	for k := range consolidatedParams {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var allParams bytes.Buffer
	// Add all parameters to the parameter string for signing
	for _, k := range keys {
		v := consolidatedParams[k]
		// Keys with same name are sorted by their values
		if len(v) > 1 {
			sort.Strings(v)
		}
		for _, val := range v {
			allParams.WriteString(k)
			allParams.WriteString("=")
			allParams.WriteString(val)
			allParams.WriteString("&")
		}
	}
	paramString := allParams.String()

	// Remove trailing ampersand
	return strings.TrimSuffix(paramString, "&")
}

// The getBaseUrlString normalizes the URL
func getBaseUrlString(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	if hostPort := strings.Split(host, ":"); len(hostPort) == 2 && (hostPort[1] == "80" || hostPort[1] == "443") {
		host = hostPort[0]
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return fmt.Sprintf("%v://%v%v", scheme, host, path)
}

// The getSignatureBaseString generates a valid signature base string as per
// https://tools.ietf.org/id/draft-eaton-oauth-bodyhash-00.html
func getSignatureBaseString(method, baseUrl, paramString string) string {
	// signature base string constructed according to 3.4.1.1
	baseParts := []string{
		// upper-case http method
		strings.ToUpper(method),
		// encoded base url
		percentEncode(baseUrl),
		// encoded parameter string
		percentEncode(paramString),
	}
	return strings.Join(baseParts, "&")
}

// The signSignatureBaseString performs the RSA signing on the given
// input string.
func signSignatureBaseString(sbs string, signingKey *rsa.PrivateKey) (string, error) {
	signature, err := crypto.Sign([]byte(sbs), signingKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// The getAuthorizationString constructs a valid Authorization header as per
// https://tools.ietf.org/html/rfc5849#section-3.5.1
func getAuthorizationString(oauthParams map[string]string) string {
	var headerBuf bytes.Buffer
	headerBuf.WriteString(authorizationPrefix)
	for k, v := range oauthParams {
		headerBuf.WriteString(k)
		headerBuf.WriteString("=\"")
		headerBuf.WriteString(v)
		headerBuf.WriteString("\",")
	}
	header := headerBuf.String()
	// Remove trailing ampersand
	return strings.TrimSuffix(header, ",")
}
