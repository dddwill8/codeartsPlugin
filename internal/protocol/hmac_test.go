package protocol

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSignRequestBenefitHeadersInSignedHeadersAndMatchesCanonicalHMAC(t *testing.T) {
	body := []byte(`{"model":"glm-5.3-flash","messages":[{"role":"user","content":"hi"}],"stream":false}`)
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	cred := SignCredential{
		AccessKeyID:     "AKIDTEST",
		SecretAccessKey: "sk-test-secret",
		SecurityToken:   "sts-token-1",
	}

	req, err := http.NewRequest(http.MethodPost, "https://snap-access.cn-north-4.myhuaweicloud.com/api/v2/chat/completions", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	ApplyBenefitHeaders(req, true, "glm-5.3-flash")
	SignRequest(req, body, cred, SignOptions{Date: at})

	authz := req.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "SDK-HMAC-SHA256 Access=") {
		t.Fatalf("Authorization = %q", authz)
	}
	signed := ParseSignedHeaders(authz)
	for _, h := range []string{"maas_type", "model-id", "model-name", "x-sdk-date", "x-sdk-content-sha256", "x-security-token"} {
		if !containsHeader(signed, h) {
			t.Fatalf("SignedHeaders %q missing %s", signed, h)
		}
	}
	if !strings.HasSuffix(CanonicalURI(req.URL.EscapedPath()), "/") {
		t.Fatalf("CanonicalURI must end with /: %s", CanonicalURI(req.URL.EscapedPath()))
	}

	canonHeaders, signedFromReq := CanonicalHeaders(req)
	if signedFromReq != signed {
		t.Fatalf("SignedHeaders mismatch: auth=%q headers=%q", signed, signedFromReq)
	}
	payloadHash := req.Header.Get("X-Sdk-Content-Sha256")
	if payloadHash != SHA256Hex(body) {
		t.Fatalf("payload hash = %s want %s", payloadHash, SHA256Hex(body))
	}
	canonical := CanonicalRequest(
		req.Method,
		CanonicalURI(req.URL.EscapedPath()),
		CanonicalQuery(req.URL.RawQuery),
		canonHeaders,
		signedFromReq,
		payloadHash,
	)
	stringToSign := StringToSign(req.Header.Get("X-Sdk-Date"), canonical)
	mac := hmac.New(sha256.New, []byte(cred.SecretAccessKey))
	_, _ = mac.Write([]byte(stringToSign))
	wantSig := hex.EncodeToString(mac.Sum(nil))
	gotSig := ParseSignature(authz)
	if gotSig != wantSig {
		t.Fatalf("Signature = %s want %s\ncanonical=\n%s", gotSig, wantSig, canonical)
	}
	if req.Header.Get("X-Sdk-Date") != "20260304T050607Z" {
		t.Fatalf("X-Sdk-Date = %s", req.Header.Get("X-Sdk-Date"))
	}
}

func containsHeader(signed, name string) bool {
	for _, p := range strings.Split(signed, ";") {
		if p == name {
			return true
		}
	}
	return false
}
