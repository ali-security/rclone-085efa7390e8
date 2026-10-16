package s3

// This verifies AWS Signature Version 4 requests against a secret
// supplied by the caller.
//
// The gofakes3 signature package can only verify a request against
// the keys registered in its key store with StoreKeys. That store is
// shared by every serve s3 instance in the process and is keyed on the
// access key ID alone, so the secrets returned by the auth proxy must
// never be put in it. This is the equivalent of
// signature.V4SignVerifyWithSecret from later versions of gofakes3 and
// follows the gofakes3 V4SignVerify algorithm exactly apart from where
// the secret comes from.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rclone/gofakes3/signature"
)

const (
	sigV4Algorithm        = "AWS4-HMAC-SHA256"
	sigV4ISO8601Format    = "20060102T150405Z"
	sigV4DateFormat       = "20060102"
	sigV4Service          = "s3"
	sigV4Request          = "aws4_request"
	sigV4UnsignedPayload  = "UNSIGNED-PAYLOAD"
	sigV4EmptySHA256      = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	sigV4HeaderAuth       = "Authorization"
	sigV4HeaderDate       = "Date"
	sigV4ContentSha256    = "X-Amz-Content-Sha256"
	sigV4AmzDate          = "X-Amz-Date"
	sigV4AmzAlgorithm     = "X-Amz-Algorithm"
	sigV4AmzCredential    = "X-Amz-Credential"
	sigV4AmzSignedHeaders = "X-Amz-SignedHeaders"
	sigV4AmzSignature     = "X-Amz-Signature"
	sigV4AmzExpires       = "X-Amz-Expires"
)

// Errors returned by v4SignVerifyWithSecret
var (
	errSignatureDoesNotMatch = errors.New("SignatureDoesNotMatch")
	errSigMissingCredential  = errors.New("InvalidRequest: missing Credential field")
	errSigCredMalformed      = errors.New("AuthorizationQueryParametersError: malformed Credential")
	errSigUnsignedHeaders    = errors.New("AccessDenied: there were headers present in the request which were not signed")
	errSigMissingDate        = errors.New("AccessDenied: AWS authentication requires a valid Date or x-amz-date header")
	errSigMalformedDate      = errors.New("MalformedDate")
	errSigMalformedExpires   = errors.New("MalformedExpires")
	errSigExpiredRequest     = errors.New("AccessDenied: request has expired")
)

// v4SignVerifyWithSecret verifies the request's signature against
// secretKey regardless of the access key ID in the request and without
// consulting the keys registered with gofakes3.
//
// It returns nil if the signature matches, errSignatureDoesNotMatch if
// the signature was well formed but not made with secretKey, or
// another error if the request could not be checked.
func v4SignVerifyWithSecret(r *http.Request, secretKey string) error {
	queryf := r.URL.Query()
	isUnsignedPayload := r.Header.Get(sigV4ContentSha256) == sigV4UnsignedPayload

	v4Auth := r.Header.Get(sigV4HeaderAuth)

	// If the header is empty but the query string has the signature
	// then it is query string (presigned URL) authentication which is
	// always "UNSIGNED-PAYLOAD"
	if v4Auth == "" && queryf.Get(sigV4AmzSignature) != "" {
		isUnsignedPayload = true
		if queryf.Get(sigV4AmzCredential) == "" {
			return errSigMissingCredential
		}
		v4Auth = fmt.Sprintf("%s Credential=%s, SignedHeaders=%s, Signature=%s", queryf.Get(sigV4AmzAlgorithm), queryf.Get(sigV4AmzCredential), queryf.Get(sigV4AmzSignedHeaders), queryf.Get(sigV4AmzSignature))
	}

	// Parse and validate the signature version 4 header
	signV4Values, errCode := signature.ParseSignV4(v4Auth)
	if errCode != signature.ErrNone {
		return errors.New(signature.GetAPIError(errCode).Code)
	}
	scopeDate, region, err := sigV4CredentialScope(v4Auth)
	if err != nil {
		return err
	}

	// Extract all the signed headers along with their values
	extractedSignedHeaders, err := sigV4ExtractSignedHeaders(signV4Values.SignedHeaders, r)
	if err != nil {
		return err
	}

	// Extract the date from the possible sources
	date := r.Header.Get(sigV4AmzDate)
	if date == "" {
		date = r.Header.Get(sigV4HeaderDate)
	}
	if date == "" {
		date = queryf.Get(sigV4AmzDate)
	}
	if date == "" {
		return errSigMissingDate
	}
	t, err := time.Parse(sigV4ISO8601Format, date)
	if err != nil {
		return errSigMalformedDate
	}

	// Check expiry
	expires := 15 * time.Minute
	if expiresStr := queryf.Get(sigV4AmzExpires); expiresStr != "" {
		expiresInt, err := strconv.ParseInt(expiresStr, 10, 64)
		if err != nil {
			return errSigMalformedExpires
		}
		expires = time.Duration(expiresInt) * time.Second
	}
	if signature.TimeNow().After(t.Add(expires)) {
		return errSigExpiredRequest
	}

	// Query string without the signature
	queryf.Del(sigV4AmzSignature)
	rawQuery := queryf.Encode()

	// Work out the signature
	hashedPayload := sigV4UnsignedPayload
	if !isUnsignedPayload {
		hashedPayload = sigV4EmptySHA256
		if v, ok := r.Header[sigV4ContentSha256]; ok {
			hashedPayload = v[0]
		}
	}
	scope := strings.Join([]string{scopeDate.Format(sigV4DateFormat), region, sigV4Service, sigV4Request}, "/")
	canonicalRequest := sigV4CanonicalRequest(extractedSignedHeaders, hashedPayload, rawQuery, r.URL.Path, r.Method)
	stringToSign := sigV4StringToSign(canonicalRequest, t, scope)
	signingKey := sigV4SigningKey(secretKey, scopeDate, region)
	newSignature := hex.EncodeToString(sigV4HMAC(signingKey, []byte(stringToSign)))

	// Verify the signature matches in constant time
	if subtle.ConstantTimeCompare([]byte(newSignature), []byte(signV4Values.Signature)) != 1 {
		return errSignatureDoesNotMatch
	}
	return nil
}

// sigV4CredentialScope returns the date and region from the Credential
// in a signature version 4 header which has already been validated by
// signature.ParseSignV4.
//
// example: Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request
func sigV4CredentialScope(v4Auth string) (date time.Time, region string, err error) {
	rawCred := strings.ReplaceAll(strings.TrimPrefix(v4Auth, sigV4Algorithm), " ", "")
	authFields := strings.Split(strings.TrimSpace(rawCred), ",")
	creds, ok := strings.CutPrefix(authFields[0], "Credential=")
	if !ok {
		return date, "", errSigCredMalformed
	}
	credElements := strings.Split(strings.TrimSpace(creds), "/")
	if len(credElements) < 5 {
		return date, "", errSigCredMalformed
	}
	credElements = credElements[len(credElements)-4:]
	date, err = time.Parse(sigV4DateFormat, credElements[0])
	if err != nil {
		return date, "", errSigCredMalformed
	}
	return date, credElements[1], nil
}

// sigV4ExtractSignedHeaders extracts the signed headers from the request
func sigV4ExtractSignedHeaders(signedHeaders []string, r *http.Request) (http.Header, error) {
	reqHeaders := r.Header
	reqQueries := r.URL.Query()
	// "host" is mandatory in the list of signed headers
	if !slices.Contains(signedHeaders, "host") {
		return nil, errSigUnsignedHeaders
	}
	extractedSignedHeaders := make(http.Header)
	for _, header := range signedHeaders {
		val, ok := reqHeaders[http.CanonicalHeaderKey(header)]
		if !ok {
			// try to set headers from the query string
			val, ok = reqQueries[header]
		}
		if ok {
			extractedSignedHeaders[http.CanonicalHeaderKey(header)] = val
			continue
		}
		switch header {
		case "expect":
			// The Go http server strips off the Expect header so
			// assume it was "100-continue" which is the only
			// expectation defined.
			extractedSignedHeaders.Set(header, "100-continue")
		case "host":
			// The Go http server removes "host" from Request.Header
			extractedSignedHeaders.Set(header, r.Host)
		case "transfer-encoding":
			// The Go http server removes "transfer-encoding" from Request.Header
			extractedSignedHeaders[http.CanonicalHeaderKey(header)] = r.TransferEncoding
		case "content-length":
			// Some clients sign Content-Length even though the spec
			// excludes it
			extractedSignedHeaders.Set(header, strconv.FormatInt(r.ContentLength, 10))
		default:
			return nil, errSigUnsignedHeaders
		}
	}
	return extractedSignedHeaders, nil
}

// sigV4CanonicalRequest generates a canonical request of the form
//
//	<HTTPMethod>\n
//	<CanonicalURI>\n
//	<CanonicalQueryString>\n
//	<CanonicalHeaders>\n
//	<SignedHeaders>\n
//	<HashedPayload>
func sigV4CanonicalRequest(extractedSignedHeaders http.Header, payload, queryStr, urlPath, method string) string {
	rawQuery := strings.ReplaceAll(queryStr, "+", "%20")
	return strings.Join([]string{
		method,
		sigV4EncodePath(urlPath),
		rawQuery,
		sigV4CanonicalHeaders(extractedSignedHeaders),
		sigV4SignedHeaders(extractedSignedHeaders),
		payload,
	}, "\n")
}

// sigV4CanonicalHeaders generates the sorted list of request headers with their values
func sigV4CanonicalHeaders(signedHeaders http.Header) string {
	var headers []string
	vals := make(http.Header)
	for k, vv := range signedHeaders {
		headers = append(headers, strings.ToLower(k))
		vals[strings.ToLower(k)] = vv
	}
	sort.Strings(headers)

	var buf bytes.Buffer
	for _, k := range headers {
		buf.WriteString(k)
		buf.WriteByte(':')
		for idx, v := range vals[k] {
			if idx > 0 {
				buf.WriteByte(',')
			}
			// Trim leading and trailing spaces and compress
			// sequential spaces into one
			buf.WriteString(strings.Join(strings.Fields(v), " "))
		}
		buf.WriteByte('\n')
	}
	return buf.String()
}

// sigV4SignedHeaders generates the alphabetically sorted, semicolon
// separated list of lowercase request header names
func sigV4SignedHeaders(signedHeaders http.Header) string {
	var headers []string
	for k := range signedHeaders {
		headers = append(headers, strings.ToLower(k))
	}
	sort.Strings(headers)
	return strings.Join(headers, ";")
}

// sigV4StringToSign generates the string to sign
func sigV4StringToSign(canonicalRequest string, t time.Time, scope string) string {
	canonicalRequestBytes := sha256.Sum256([]byte(canonicalRequest))
	return sigV4Algorithm + "\n" + t.Format(sigV4ISO8601Format) + "\n" + scope + "\n" + hex.EncodeToString(canonicalRequestBytes[:])
}

// sigV4SigningKey generates the HMAC key used to calculate the signature
func sigV4SigningKey(secretKey string, t time.Time, region string) []byte {
	date := sigV4HMAC([]byte("AWS4"+secretKey), []byte(t.Format(sigV4DateFormat)))
	regionBytes := sigV4HMAC(date, []byte(region))
	service := sigV4HMAC(regionBytes, []byte(sigV4Service))
	return sigV4HMAC(service, []byte(sigV4Request))
}

// sigV4HMAC returns the HMAC-SHA256 of data with key
func sigV4HMAC(key []byte, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// if the path matches this then there is no need to encode it
var sigV4ReservedObjectNames = regexp.MustCompile("^[a-zA-Z0-9-_.~/]+$")

// sigV4EncodePath encodes the path from UTF-8 byte representations
// to HTML hex escape sequences as in minio/s3utils.EncodePath
func sigV4EncodePath(pathName string) string {
	if sigV4ReservedObjectNames.MatchString(pathName) {
		return pathName
	}
	var encodedPathname strings.Builder
	for _, s := range pathName {
		if 'A' <= s && s <= 'Z' || 'a' <= s && s <= 'z' || '0' <= s && s <= '9' { // §2.3 Unreserved characters (mark)
			encodedPathname.WriteRune(s)
			continue
		}
		switch s {
		case '-', '_', '.', '~', '/': // §2.3 Unreserved characters (mark)
			encodedPathname.WriteRune(s)
			continue
		default:
			n := utf8.RuneLen(s)
			if n < 0 {
				// if utf8 cannot convert return the same string as is
				return pathName
			}
			u := make([]byte, n)
			utf8.EncodeRune(u, s)
			for _, r := range u {
				encodedPathname.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{r})))
			}
		}
	}
	return encodedPathname.String()
}
