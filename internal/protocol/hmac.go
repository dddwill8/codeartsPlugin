package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// SignCredential is the STS (or permanent) AK/SK used for SDK-HMAC-SHA256.
type SignCredential struct {
	AccessKeyID     string
	SecretAccessKey string
	SecurityToken   string
}

// SignOptions controls deterministic signing for tests.
type SignOptions struct {
	// Date, if non-zero, is used as X-Sdk-Date instead of time.Now.
	Date time.Time
}

// SignRequest adds X-Sdk-Date, X-Security-Token, X-Sdk-Content-Sha256, Host,
// and Authorization (SDK-HMAC-SHA256). Every header on req except Authorization
// is signed. CanonicalURI always ends with "/".
func SignRequest(req *http.Request, body []byte, cred SignCredential, opts SignOptions) {
	if req == nil {
		return
	}
	at := opts.Date
	if at.IsZero() {
		at = time.Now().UTC()
	} else {
		at = at.UTC()
	}
	xDate := at.Format("20060102T150405Z")
	req.Header.Set("X-Sdk-Date", xDate)
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	req.Header.Set("Host", host)
	if cred.SecurityToken != "" {
		req.Header.Set("X-Security-Token", cred.SecurityToken)
	}
	if body == nil {
		body = []byte{}
	}
	payloadHash := SHA256Hex(body)
	req.Header.Set("X-Sdk-Content-Sha256", payloadHash)

	canonicalHeaders, signedHeaders := CanonicalHeaders(req)
	canonicalRequest := CanonicalRequest(
		req.Method,
		CanonicalURI(req.URL.EscapedPath()),
		CanonicalQuery(req.URL.RawQuery),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	)
	stringToSign := StringToSign(xDate, canonicalRequest)
	signature := HMACHex(cred.SecretAccessKey, stringToSign)
	req.Header.Set("Authorization", SigningAlgorithm+
		" Access="+cred.AccessKeyID+
		", SignedHeaders="+signedHeaders+
		", Signature="+signature)
}

// CanonicalHeaders returns the signed header block (lowercase keys, sorted)
// and the SignedHeaders list. All request headers participate.
func CanonicalHeaders(req *http.Request) (headers, signed string) {
	keys := make([]string, 0, len(req.Header))
	seen := make(map[string]struct{}, len(req.Header))
	for k := range req.Header {
		lk := strings.ToLower(k)
		if lk == "authorization" {
			continue
		}
		if _, ok := seen[lk]; ok {
			continue
		}
		seen[lk] = struct{}{}
		keys = append(keys, lk)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		v := req.Header.Get(k)
		sb.WriteString(k + ":" + strings.TrimSpace(v) + "\n")
	}
	return sb.String(), strings.Join(keys, ";")
}

// CanonicalURI percent-encodes each path segment and always ends with "/".
func CanonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		segments[i] = url.PathEscape(seg)
	}
	out := strings.Join(segments, "/")
	if !strings.HasSuffix(out, "/") {
		out += "/"
	}
	return out
}

// CanonicalQuery sorts query parameters.
func CanonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return raw
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		vs := vals[k]
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

// CanonicalRequest is the Huawei SDK canonical request string.
func CanonicalRequest(method, canonicalURI, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash string) string {
	return strings.Join([]string{
		method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")
}

// StringToSign is algorithm + date + hex(sha256(canonicalRequest)).
func StringToSign(xDate, canonicalRequest string) string {
	return strings.Join([]string{
		SigningAlgorithm,
		xDate,
		SHA256Hex([]byte(canonicalRequest)),
	}, "\n")
}

// SHA256Hex returns the lowercase hex SHA-256 of b.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// HMACHex returns lowercase hex HMAC-SHA256(key, msg).
func HMACHex(key, msg string) string {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(msg))
	return hex.EncodeToString(mac.Sum(nil))
}

// ParseSignedHeaders extracts the SignedHeaders list from an Authorization value.
func ParseSignedHeaders(authorization string) string {
	const marker = "SignedHeaders="
	i := strings.Index(authorization, marker)
	if i < 0 {
		return ""
	}
	rest := authorization[i+len(marker):]
	if j := strings.Index(rest, ","); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

// ParseSignature extracts the Signature hex from an Authorization value.
func ParseSignature(authorization string) string {
	const marker = "Signature="
	i := strings.Index(authorization, marker)
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(authorization[i+len(marker):])
}
