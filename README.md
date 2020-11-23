# oauth1-signer-go

[![](https://github.com/Mastercard/oauth1-signer-go/workflows/Build%20&%20Test/badge.svg)](https://github.com/Mastercard/oauth1-signer-go/actions?query=workflow%3A%22Build+%26+Test%22)
[![](https://goreportcard.com/badge/github.com/Mastercard/oauth1-signer-go)](https://goreportcard.com/report/github.com/Mastercard/oauth1-signer-go)
[![](https://sonarcloud.io/api/project_badges/measure?project=Mastercard_oauth1-signer-go&metric=alert_status)](https://sonarcloud.io/dashboard?id=Mastercard_oauth1-signer-go)
[![](https://github.com/Mastercard/oauth1-signer-go/workflows/broken%20links%3F/badge.svg)](https://github.com/Mastercard/oauth1-signer-go/actions?query=workflow%3A%22broken+links%3F%22)
[![](https://img.shields.io/badge/godoc-reference-5272B4.svg)](https://godoc.org/github.com/Mastercard/oauth1-signer-go)
[![](https://img.shields.io/badge/license-MIT-yellow.svg)](https://github.com/Mastercard/oauth1-signer-go/blob/master/LICENSE)

## Table of Contents
- [Overview](#overview)
  * [Compatibility](#compatibility)
  * [References](#references)
- [Usage](#usage)
  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
  * [Loading the Signing Key](#loading-the-signing-key) 
  * [Creating the OAuth Authorization Header](#creating-the-oauth-authorization-header)
  * [Signing HTTP Request](#signing-http-request)
  * [Integrating with OpenAPI Generator API Client Libraries](#integrating-with-openapi-generator-api-client-libraries)

## Overview <a name="overview"></a>
Library for Generating a Mastercard API compliant OAuth signature.

### Compatibility <a name="compatibility"></a>
* Go 1.12+

### References <a name="references"></a>
* [OAuth 1.0a specification](https://tools.ietf.org/html/rfc5849)
* [Body hash extension for non application/x-www-form-urlencoded payloads](https://tools.ietf.org/id/draft-eaton-oauth-bodyhash-00.html)

## Usage <a name="usage"></a>
### Prerequisites <a name="prerequisites"></a>
Before using this library, you will need to set up a project in the [Mastercard Developers Portal](https://developer.mastercard.com). 

As part of this set up, you'll receive credentials for your app:
* A consumer key (displayed on the Mastercard Developer Portal)
* A private request signing key (matching the public certificate displayed on the Mastercard Developer Portal)

### Installation <a name="installation"></a>

####
```go
import github.com/mastercard/oauth1-signer-go
```

### Loading the Signing Key <a name="loading-the-signing-key"></a>

A `signingKey` can be created by calling the `utils.LoadSigningKey` function:
```go
import "github.com/mastercard/oauth1-signer-go/utils"

//...
signingKey, err := utils.LoadSigningKey(
                                    "<insert PKCS#12 key file path>", 
                                    "<insert key password>")
//...
```

### Creating the OAuth Authorization Header <a name="creating-the-oauth-authorization-header"></a>
The function that does all the heavy lifting is `OAuth.GetAuthorizationHeader`. You can call into it directly and as long as you provide the correct parameters, it will return a string that you can add into your request's `Authorization` header.

```go
import "github.com/mastercard/oauth1-signer-go"

//...
consumerKey := "<insert consumer key>"
url, _ := url.Parse("https://sandbox.api.mastercard.com/service")
method := "POST"
payload := "<insert payload>"
authHeader, err := oauth.GetAuthorizationHeader(url, method, payload, consumerKey, signingKey)
//...
```

### Signing HTTP Request <a name="signing-http-request"></a>

Alternatively, you can use helper function for http request.

Usage briefly described below, but you can also refer to the test package for examples. 

```go
import "github.com/mastercard/oauth1-signer-go"

//...
payload := "<insert payload>"
request, _ := http.NewRequest("POST", "https://sandbox.api.mastercard.com/service", payload)
signer := &oauth.Signer{
    ConsumerKey: consumerKey,
    SigningKey:  signingKey,
}
err = signer.Sign(request)
//...
```

### Integrating with OpenAPI Generator API Client Libraries <a name="integrating-with-openapi-generator-api-client-libraries"></a>

[OpenAPI Generator](https://github.com/OpenAPITools/openapi-generator) generates API client libraries from [OpenAPI Specs](https://github.com/OAI/OpenAPI-Specification). 
It provides generators and library templates for supporting multiple languages and frameworks.

The `github.com/mastercard/oauth1-signer-go/interceptor` package provides you function for http request interception you can use when configuring your API client. This function takes care of adding the correct `Authorization` header before sending the request.

Generators currently supported:
+ [Go](#go)

#### Go <a name="go"></a>
##### OpenAPI Generator

Client libraries can be generated using the following command:

```shell
java -jar openapi-generator-cli.jar generate -i openapi-spec.yaml -g go -o out
```

See also:
* [OpenAPI Generator (executable)](https://mvnrepository.com/artifact/org.openapitools/openapi-generator-cli)
* [CONFIG OPTIONS for Go](https://github.com/OpenAPITools/openapi-generator/blob/master/docs/generators/go.md)

##### Usage of the github.com/mastercard/oauth1-signer-go/interceptor

```go
import "github.com/mastercard/oauth1-signer-go/interceptor"

//...
configuration := openapi.NewConfiguration()
configuration.BasePath = "https://sandbox.api.mastercard.com"
httpClient, _ := interceptor.GetHttpClient("<insert consumer key>", "<insert PKCS#12 key file path>", "<insert key password>")
configuration.HTTPClient = httpClient
apiClient := openapi.NewAPIClient(configuration)

response, err = apiClient.SomeApi.doSomething()
//...
```
