package protocol

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPostChatCompletionsSendsSignedHMAC(t *testing.T) {
	var gotAuth, gotMethod, gotPath, gotMaas, gotModelID string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotMaas = r.Header.Get("maas_type")
		gotModelID = r.Header.Get("model-id")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer srv.Close()

	body, model, err := PrepareChatBody(
		[]byte(`{"model":"glm-5.3-flash","messages":[{"role":"user","content":"hi"}]}`),
		"glm-5.3-flash",
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	cred := SignCredential{AccessKeyID: "AKIDchat", SecretAccessKey: "sk-chat", SecurityToken: "sts-chat"}
	at := time.Date(2026, 4, 1, 2, 3, 4, 0, time.UTC)
	resp, err := PostChatCompletions(srv.Client(), srv.URL+"/api/v2/chat/completions", body, cred, model, true, false, SignOptions{Date: at})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %s", gotMethod)
	}
	if gotPath != "/api/v2/chat/completions" {
		t.Fatalf("path = %s", gotPath)
	}
	if !strings.HasPrefix(gotAuth, "SDK-HMAC-SHA256 Access=") {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotMaas != "benefit" || gotModelID != "glm-5.3-flash" {
		t.Fatalf("benefit headers maas=%q model-id=%q", gotMaas, gotModelID)
	}
	signed := ParseSignedHeaders(gotAuth)
	for _, h := range []string{"maas_type", "model-id", "model-name"} {
		if !containsHeader(signed, h) {
			t.Fatalf("SignedHeaders %q missing %s", signed, h)
		}
	}
	if !strings.Contains(string(gotBody), `"stream":false`) {
		t.Fatalf("body = %s", gotBody)
	}
}

func TestUpstreamChatErrorDetectsWrappedHuaweiFailure(t *testing.T) {
	if got := UpstreamChatError(200, []byte(`{"error_code":"4004","error_msg":"benefit not found","result":null}`)); got == "" {
		t.Fatal("200 benefit not found should be an error")
	}
	if got := UpstreamChatError(200, []byte(`{"id":"x","choices":[{"message":{"role":"assistant","content":"好"}}]}`)); got != "" {
		t.Fatalf("valid completion treated as error: %q", got)
	}
}
