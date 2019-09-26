package oauth

import (
	"crypto/rsa"
	"github.com/mastercard/oauth1-signer-go/authentication_utils"
	"net/url"
	"reflect"
	"testing"
)

func TestExtractQueryParams_ShouldSupportDuplicateKeysAndEmptyValues(t *testing.T) {

	// GIVEN
	u, _ := url.Parse("https://sandbox.api.mastercard.com/audiences/v1/getcountries?offset=0&offset=1&length=10&empty&odd=")

	// WHEN
	queryParams := extractQueryParams(u)

	// THEN
	if l := len(queryParams); l != 4 {
		t.Errorf("Expected len of queryParams is 4, got %v", l)
	}
	if v := queryParams["length"]; !reflect.DeepEqual(v, []string{"10"}) {
		t.Errorf("Expected queryParams[\"length\"] [10], got %v", v)
	}
	if v := queryParams["offset"]; !reflect.DeepEqual(v, []string{"0", "1"}) {
		t.Errorf("Expected queryParams[\"offset\"] [0, 1], got %v", v)
	}
	if v := queryParams["empty"]; !reflect.DeepEqual(v, []string{""}) {
		t.Errorf("Expected queryParams[\"empty\"] [], got %v", v)
	}
	if v := queryParams["odd"]; !reflect.DeepEqual(v, []string{""}) {
		t.Errorf("Expected queryParams[\"odd\"] [], got %v", v)
	}
}

func TestExtractQueryParams_ShouldSupportRfcExample_WhenUrlCreatedFromUrlString(t *testing.T) {

	// GIVEN
	u, _ := url.Parse("https://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b")

	// WHEN
	queryParams := extractQueryParams(u)

	// THEN
	if l := len(queryParams); l != 4 {
		t.Errorf("Expected len of queryParams is 4, got %v", l)
	}
	if v := queryParams["b5"]; !reflect.DeepEqual(v, []string{"%3D%253D"}) {
		t.Errorf("Expected queryParams[\"b5\"] , got %v", v)
	}
	if v := queryParams["a3"]; !reflect.DeepEqual(v, []string{"a"}) {
		t.Errorf("Expected queryParams[\"a3\"] [a], got %v", v)
	}
	if v := queryParams["c%40"]; !reflect.DeepEqual(v, []string{""}) {
		t.Errorf("Something went wrong, got %v", v)
	}
	if v := queryParams["a2"]; !reflect.DeepEqual(v, []string{"r%20b"}) {
		t.Errorf("Expected queryParams[\"a2\"] [r b], got %v", v)
	}
}

func TestExtractQueryParams_ShouldEncodeParams_WhenUrlCreatedFromStringWithEncodedParams(t *testing.T) {
	// GIVEN
	u, _ := url.Parse("https://example.com/request?colon=%3A&plus=%2B&comma=%2C")

	// WHEN
	queryParams := extractQueryParams(u)

	// THEN
	if l := len(queryParams); l != 3 {
		t.Errorf("Expected len of queryParams is 4, got %v", l)
	}
	if "colon=%3A&plus=%2B&comma=%2C" != u.RawQuery {
		t.Errorf("Something went wrong, got %v", u.RawQuery)
	}
	decoded, _ := url.QueryUnescape(u.RawQuery)
	if "colon=:&plus=+&comma=," != decoded {
		t.Errorf("Something went wrong, got %v", decoded)
	}
	if v := queryParams["colon"]; !reflect.DeepEqual(v, []string{"%3A"}) {
		t.Errorf("Expected queryParams[\"colon\"] [], got %v", v)
	}
	if v := queryParams["plus"]; !reflect.DeepEqual(v, []string{"%2B"}) {
		t.Errorf("Expected queryParams[\"plus\"] [], got %v", v)
	}
	if v := queryParams["comma"]; !reflect.DeepEqual(v, []string{"%2C"}) {
		t.Errorf("Expected queryParams[\"comma\"] [], got %v", v)
	}
}

func TestParameterEncoding_ShouldCreateExpectedSignatureBaseString_WhenQueryParamsEncodedInUrl(t *testing.T) {

	// GIVEN
	u, _ := url.Parse("https://example.com/?param=token1%3Atoken2")

	// WHEN
	queryParams := extractQueryParams(u)
	paramString := toOauthParamString(queryParams, map[string]string{})
	baseString := getSignatureBaseString("GET", "https://example.com", paramString)

	// THEN
	if "GET&https%3A%2F%2Fexample.com&param%3Dtoken1%253Atoken2" != baseString {
		t.Errorf("Something went wrong got, %v", baseString)
	}
}

func TestParameterEncoding_ShouldCreateExpectedSignatureBaseString_WhenQueryParamsNotEncodedInUrl(t *testing.T) {

	// GIVEN
	u, _ := url.Parse("https://example.com/?param=token1:token2")

	// WHEN
	queryParams := extractQueryParams(u)
	paramString := toOauthParamString(queryParams, map[string]string{})
	baseString := getSignatureBaseString("GET", "https://example.com", paramString)

	// THEN
	if "GET&https%3A%2F%2Fexample.com&param%3Dtoken1%3Atoken2" != baseString {
		t.Errorf("Something went wrong got, %v", baseString)
	}
}

func TestGetBodyHash(t *testing.T) {

	bodyHash := getBodyHash([]byte{})
	if "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=" != bodyHash {
		t.Errorf("Something went wrong got, %v", bodyHash)
	}
	bodyHash = getBodyHash([]byte{})
	if "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=" != bodyHash {
		t.Errorf("Something went wrong got, %v", bodyHash)
	}
	bodyHash = getBodyHash([]byte("{\"foõ\":\"bar\"}"))
	if "+Z+PWW2TJDnPvRcTgol+nKO3LT7xm8smnsg+//XMIyI=" != bodyHash {
		t.Errorf("Something went wrong got, %v", bodyHash)
	}
}

func TestGetOAuthParamString_ShouldSupportRfcExample(t *testing.T) {
	params := make(map[string][]string)
	params["b5"] = []string{"%3D%253D"}
	params["a3"] = []string{"a", "2%20q"}
	params["c%40"] = []string{""}
	params["a2"] = []string{"r%20b"}
	params["c2"] = []string{""}

	oauthParams := make(map[string]string)
	oauthParams["oauth_consumer_key"] = "9djdj82h48djs9d2"
	oauthParams["oauth_token"] = "kkk9d7dh3k39sjv7"
	oauthParams["oauth_signature_method"] = "HMAC-SHA1"
	oauthParams["oauth_timestamp"] = "137131201"
	oauthParams["oauth_nonce"] = "7d8f3e4a"

	paramString := toOauthParamString(params, oauthParams)
	expectedParams := "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"

	if expectedParams != paramString {
		t.Errorf("Something went wrong got, %v", paramString)
	}
}

func TestGetOAuthParamString_ShouldUseAscendingByteValueOrdering(t *testing.T) {
	params := make(map[string][]string)
	params["b"] = []string{"b"}
	params["A"] = []string{"a", "A"}
	params["B"] = []string{"B"}
	params["a"] = []string{"A", "a"}
	params["0"] = []string{"0"}

	oauthParams := make(map[string]string)
	paramString := toOauthParamString(params, oauthParams)

	if "0=0&A=A&A=a&B=B&a=A&a=a&b=b" != paramString {
		t.Errorf("Something went wrong got, %v", paramString)
	}
}

func TestGetBaseUrlString_ShouldSupportRfcExamples(t *testing.T) {
	URL, _ := url.Parse("https://www.example.net:8080")
	baseUrl := getBaseUrlString(URL)
	if "https://www.example.net:8080/" != baseUrl {
		t.Errorf("Something went wrong got, %v", baseUrl)
	}

	URL, _ = url.Parse("http://EXAMPLE.COM:80/r%20v/X?id=123")
	baseUrl = getBaseUrlString(URL)
	// /!\ According to https://tools.ietf.org/html/rfc5849#section-3.4.1.2 it seems we should get "r%20v", not "r%2520v"
	if "http://example.com/r%20v/X" != baseUrl {
		t.Errorf("Something went wrong got, %v", baseUrl)
	}
}

func TestGetBaseUrlString_ShouldRemoveRedundantPorts(t *testing.T) {
	URL, _ := url.Parse("https://api.mastercard.com:443/test?query=param")
	baseUrl := getBaseUrlString(URL)
	if "https://api.mastercard.com/test" != baseUrl {
		t.Errorf("Something went wrong got, %v", baseUrl)
	}
	URL, _ = url.Parse("http://api.mastercard.com:80/test")
	baseUrl = getBaseUrlString(URL)
	if "http://api.mastercard.com/test" != baseUrl {
		t.Errorf("Something went wrong got, %v", baseUrl)
	}
	URL, _ = url.Parse("https://api.mastercard.com:17443/test?query=param")
	baseUrl = getBaseUrlString(URL)
	if "https://api.mastercard.com:17443/test" != baseUrl {
		t.Errorf("Something went wrong got, %v", baseUrl)
	}
}

func TestGetBaseUrlString_ShouldRemoveFragments(t *testing.T) {
	URL, _ := url.Parse("https://api.mastercard.com/test?query=param#fragment")
	baseUrl := getBaseUrlString(URL)
	if "https://api.mastercard.com/test" != baseUrl {
		t.Errorf("Something went wrong got, %v", baseUrl)
	}
}

func TestGetBaseUrlString_ShouldAddTrailingSlash(t *testing.T) {
	u, _ := url.Parse("https://api.mastercard.com")
	baseUrl := getBaseUrlString(u)
	if "https://api.mastercard.com/" != baseUrl {
		t.Errorf("Something went wrong got, %v", baseUrl)
	}
}

func TestGetBaseUrlString_ShouldUseLowercaseSchemesAndHosts(t *testing.T) {
	u, _ := url.Parse("HTTPS://API.MASTERCARD.COM/TEST")
	baseUrl := getBaseUrlString(u)
	if "https://api.mastercard.com/TEST" != baseUrl {
		t.Errorf("Something went wrong got, %v", baseUrl)
	}
}

func TestGetSignatureBaseString_Nominal(t *testing.T) {
	params := make(map[string][]string)
	params["param2"] = []string{"hello"}
	params["first_param"] = []string{"value", "othervalue"}

	oauthParams := make(map[string]string)
	oauthParams["oauth_nonce"] = "randomnonce"
	oauthParams["oauth_body_hash"] = "body/hash"

	paramString := toOauthParamString(params, oauthParams)
	signatureBaseString := getSignatureBaseString("POST", "https://api.mastercard.com", paramString)

	expectedSbs := "POST&https%3A%2F%2Fapi.mastercard.com&first_param%3Dothervalue%26first_param%3Dvalue%26oauth_body_hash%3Dbody%2Fhash%26oauth_nonce%3Drandomnonce%26param2%3Dhello"

	if expectedSbs != signatureBaseString {
		t.Errorf("Something went wrong got, %v", signatureBaseString)
	}
}

func TestSignSignatureBaseString(t *testing.T) {
	expectedSignatureString := "IJeNKYGfUhFtj5OAPRI92uwfjJJLCej3RCMLbp7R6OIYJhtwxnTkloHQ2bgV7fks4GT/A7rkqrgUGk0ewbwIC6nS3piJHyKVc7rvQXZuCQeeeQpFzLRiH3rsb+ZS+AULK+jzDje4Fb+BQR6XmxuuJmY6YrAKkj13Ln4K6bZJlSxOizbNvt+Htnx+hNd4VgaVBeJKcLhHfZbWQxK76nMnjY7nDcM/2R6LUIR2oLG1L9m55WP3bakAvmOr392ulv1+mWCwDAZZzQ4lakDD2BTu0ZaVsvBW+mcKFxYeTq7SyTQMM4lEwFPJ6RLc8jJJ+veJXHekLVzWg4qHRtzNBLz1mA=="
	s, _ := signSignatureBaseString("baseString", getTestSigningKey())
	if expectedSignatureString != s {
		t.Errorf("Something went wrong got, %v", s)
	}
}

func getTestSigningKey() *rsa.PrivateKey {
	signingKey, _ := authentication_utils.LoadSigningKey("testdata/test_key_container.p12", "Password1")
	return signingKey
}

func TestSignSignatureBaseString_ShouldThrowIllegalStateException_WhenInvalidKey(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("It should panic in case of a nil private key")
		}
	}()
	_, _ = signSignatureBaseString("some string", nil)
	t.Errorf("It should panic in case of a nil private key")
}

func TestGetSignatureBaseString_Integrated(t *testing.T) {
	body := "<?xml version=\"1.0\" encoding=\"Windows-1252\"?><ns2:TerminationInquiryRequest xmlns:ns2=\"http://mastercard.com/termination\"><AcquirerId>1996</AcquirerId><TransactionReferenceNumber>1</TransactionReferenceNumber><Merchant><Name>TEST</Name><DoingBusinessAsName>TEST</DoingBusinessAsName><PhoneNumber>5555555555</PhoneNumber><NationalTaxId>1234567890</NationalTaxId><Address><Line1>5555 Test Lane</Line1><City>TEST</City><CountrySubdivision>XX</CountrySubdivision><PostalCode>12345</PostalCode><Country>USA</Country></Address><Principal><FirstName>John</FirstName><LastName>Smith</LastName><NationalId>1234567890</NationalId><PhoneNumber>5555555555</PhoneNumber><Address><Line1>5555 Test Lane</Line1><City>TEST</City><CountrySubdivision>XX</CountrySubdivision><PostalCode>12345</PostalCode><Country>USA</Country></Address><DriversLicense><Number>1234567890</Number><CountrySubdivision>XX</CountrySubdivision></DriversLicense></Principal></Merchant></ns2:TerminationInquiryRequest>"
	method := "POST"
	urlParse, _ := url.Parse("https://sandbox.api.mastercard.com/fraud/merchant/v1/termination-inquiry?Format=XML&PageOffset=0&PageLength=10")
	oauthParams := make(map[string]string)
	oauthParams["oauth_consumer_key"] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	oauthParams["oauth_nonce"] = "1111111111111111111"
	oauthParams["oauth_signature_method"] = "RSA-SHA256"
	oauthParams["oauth_timestamp"] = "1111111111"
	oauthParams["oauth_version"] = "1.0"
	oauthParams["oauth_body_hash"] = getBodyHash([]byte(body))

	queryParams := extractQueryParams(urlParse)
	paramString := toOauthParamString(queryParams, oauthParams)
	baseUrl := getBaseUrlString(urlParse)
	baseString := getSignatureBaseString(method, baseUrl, paramString)
	expected := "POST&https%3A%2F%2Fsandbox.api.mastercard.com%2Ffraud%2Fmerchant%2Fv1%2Ftermination-inquiry&Format%3DXML%26PageLength%3D10%26PageOffset%3D0%26oauth_body_hash%3Dh2Pd7zlzEZjZVIKB4j94UZn%2FxxoR3RoCjYQ9%2FJdadGQ%3D%26oauth_consumer_key%3Dxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx%26oauth_nonce%3D1111111111111111111%26oauth_signature_method%3DRSA-SHA256%26oauth_timestamp%3D1111111111%26oauth_version%3D1.0"
	if expected != baseString {
		t.Errorf("Something went wrong got, %v", baseUrl)
	}
}

func TestPercentEncode(t *testing.T) {
	if "Format%3DXML" != PercentEncode("Format=XML") {
		t.Errorf("Something went wrong got, %v", PercentEncode("Format=XML"))
	}
	if "WhqqH%2BTU95VgZMItpdq78BWb4cE%3D" != PercentEncode("WhqqH+TU95VgZMItpdq78BWb4cE=") {
		t.Errorf("Something went wrong got, %v", PercentEncode("WhqqH+TU95VgZMItpdq78BWb4cE="))
	}
	if "WhqqH%2BTU95VgZMItpdq78BWb4cE%3D%26o" != PercentEncode("WhqqH+TU95VgZMItpdq78BWb4cE=&o") {
		t.Errorf("Something went wrong got, %v", PercentEncode("WhqqH+TU95VgZMItpdq78BWb4cE=&o"))
	}
	if "WhqqH%2BTU95VgZ~Itpdq78BWb4cE%3D%26o" != PercentEncode("WhqqH+TU95VgZ~Itpdq78BWb4cE=&o") { // Tilde stays unescaped
		t.Errorf("Something went wrong got, %v", PercentEncode("WhqqH+TU95VgZ~Itpdq78BWb4cE=&o"))
	}
}

func TestGetNonce_ShouldBeUniqueAndHaveLengthOf16(t *testing.T) {
	nonce := getNonce()
	if len(nonce) != nonceLength {
		t.Errorf("Something went wrong got, %v", len(nonce))
	}
}
