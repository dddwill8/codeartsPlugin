package protocol

import (
	"encoding/json"
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

func TestPrepareChatBodyRewritesNamedToolChoice(t *testing.T) {
	raw := []byte(`{
		"model":"codearts/DeepSeek-V4.1-Flash-1017",
		"messages":[{"role":"user","content":[{"type":"text","text":"weather"}]}],
		"max_completion_tokens":128,
		"frequency_penalty":0.2,
		"tools":[
			{"type":"function","function":{"name":"delete_file","parameters":{"type":"object"}}},
			{"type":"function","function":{"name":"get_weather","description":"weather only","parameters":{"type":"object"}}}
		],
		"tool_choice":{"type":"function","function":{"name":"get_weather"}}
	}`)
	body, model, err := PrepareChatBody(raw, "DeepSeek-V4.1-Flash-1017", true)
	if err != nil {
		t.Fatal(err)
	}
	if model != "DeepSeek-V4.1-Flash-1017" {
		t.Fatalf("model = %q", model)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["tool_choice"] != "required" {
		t.Fatalf("tool_choice = %#v", got["tool_choice"])
	}
	if _, ok := got["frequency_penalty"]; ok {
		t.Fatalf("unknown field forwarded: %s", body)
	}
	if got["max_tokens"] != float64(128) {
		t.Fatalf("max_tokens = %#v", got["max_tokens"])
	}
	if _, ok := got["max_completion_tokens"]; ok {
		t.Fatalf("max_completion_tokens was forwarded: %s", body)
	}
	tools, _ := got["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools = %#v", tools)
	}
	fn := tools[0].(map[string]any)["function"].(map[string]any)
	if fn["name"] != "get_weather" || fn["description"] != "weather only" {
		t.Fatalf("selected tool = %#v", fn)
	}
	msgs := got["messages"].([]any)
	content := msgs[0].(map[string]any)["content"].([]any)
	if content[0].(map[string]any)["type"] != "text" {
		t.Fatalf("content was flattened: %#v", msgs[0])
	}
}

func TestPrepareChatBodyRejectsUnknownNamedTool(t *testing.T) {
	raw := []byte(`{
		"messages":[{"role":"user","content":"hi"}],
		"tools":[{"type":"function","function":{"name":"other"}}],
		"tool_choice":{"type":"function","function":{"name":"target"}}
	}`)
	if _, _, err := PrepareChatBody(raw, "GLM-5.3", false); err == nil || !strings.Contains(err.Error(), "not defined") {
		t.Fatalf("err = %v", err)
	}
}

func TestPrepareChatBodyDropsUnpairedToolHistory(t *testing.T) {
	raw := []byte(`{
		"messages":[
			{"role":"user","content":"hi"},
			{"role":"assistant","content":null,"tool_calls":[{"id":"call_old","type":"function","function":{"name":"bash","arguments":"{}"}}]},
			{"role":"assistant","content":"ok","tool_calls":[{"id":"call_done","type":"function","function":{"name":"bash","arguments":"{}"}}]},
			{"role":"tool","tool_call_id":"call_done","content":"/workspace"},
			{"role":"tool","tool_call_id":"call_orphan","content":"drop me"}
		]
	}`)
	body, _, err := PrepareChatBody(raw, "DeepSeek-V4.1-Flash-1017", false)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Messages []map[string]any `json:"messages"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Messages) != 4 {
		t.Fatalf("messages = %#v", got.Messages)
	}
	if _, ok := got.Messages[1]["tool_calls"]; ok {
		t.Fatalf("unpaired tool_calls kept: %#v", got.Messages[1])
	}
	if got.Messages[2]["reasoning_content"] != "" {
		t.Fatalf("reasoning_content = %#v", got.Messages[2]["reasoning_content"])
	}
	if got.Messages[3]["tool_call_id"] != "call_done" {
		t.Fatalf("tool result = %#v", got.Messages[3])
	}
	if strings.Contains(string(body), "call_orphan") || strings.Contains(string(body), "call_old") {
		t.Fatalf("orphan history forwarded: %s", body)
	}
}

func TestParamInvalidDetectsInferHubCode(t *testing.T) {
	if !ParamInvalid("InferHub.001001005.400 The request param is invalid") {
		t.Fatal("expected param invalid")
	}
	if ParamInvalid("InferHub.002002009.404 Route missed") {
		t.Fatal("route miss is not a param error")
	}
}
