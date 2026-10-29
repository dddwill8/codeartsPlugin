package dispatch

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dddwill8/codeartsPlugin/internal/protocol"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
)

type chatCapture struct {
	model   string
	modelID string
	maas    []string
}

func chatServer(t *testing.T, cap *chatCapture) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		cap.model, _ = m["model"].(string)
		cap.modelID = r.Header.Get("model-id")
		cap.maas = append(cap.maas, r.Header.Get("maas_type"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	t.Cleanup(srv.Close)
	SetEndpoints(endpointOverride{SnapEngine: srv.URL})
	SetHTTPClient(srv.Client())
}

func prefixedExecute(t *testing.T, extra map[string]any, storageExtra map[string]any) {
	t.Helper()
	cred := protocol.Credential{Type: protocol.Provider, UserID: "u-prefix", AccessKeyID: "AK", SecretAccessKey: "sk", SecurityToken: "st"}
	storage, err := protocol.MarshalCredential(cred)
	if err != nil {
		t.Fatal(err)
	}
	if len(storageExtra) > 0 {
		var m map[string]any
		_ = json.Unmarshal(storage, &m)
		for k, v := range storageExtra {
			m[k] = v
		}
		storage, _ = json.Marshal(m)
	}
	req := map[string]any{
		"Payload":     []byte(`{"model":"codearts/GLM-5.3","messages":[{"role":"user","content":"hi"}]}`),
		"StorageJSON": storage,
	}
	for k, v := range extra {
		req[k] = v
	}
	raw, _ := json.Marshal(req)
	env := mustHandle(t, pluginabi.MethodExecutorExecute, raw)
	if !env.OK {
		t.Fatalf("execute failed: %+v", env.Error)
	}
}

func TestExecuteStripsConfiguredPrefix(t *testing.T) {
	cases := map[string]struct {
		extra   map[string]any
		storage map[string]any
	}{
		"metadata prefix":  {extra: map[string]any{"Model": "codearts/GLM-5.3", "AuthMetadata": map[string]any{"prefix": "codearts"}}},
		"storage prefix":   {extra: map[string]any{"Model": "codearts/GLM-5.3"}, storage: map[string]any{"prefix": "codearts"}},
		"payload only":     {extra: map[string]any{"AuthMetadata": map[string]any{"prefix": "codearts"}}},
		"host stripped id": {extra: map[string]any{"Model": "GLM-5.3", "AuthMetadata": map[string]any{"prefix": "codearts"}}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			resetForTest(t)
			var cap chatCapture
			chatServer(t, &cap)
			prefixedExecute(t, tc.extra, tc.storage)
			if cap.model != "GLM-5.3" {
				t.Fatalf("upstream model = %q", cap.model)
			}
		})
	}
}

func TestExecuteStripsUnknownPrefixForDiscoveredModel(t *testing.T) {
	resetForTest(t)
	protocol.SetAccountModels("u-prefix", []protocol.ModelInfo{{ID: "GLM-5.3", Benefit: true}})
	var cap chatCapture
	chatServer(t, &cap)
	prefixedExecute(t, map[string]any{"Model": "team/GLM-5.3"}, nil)
	if cap.model != "GLM-5.3" || cap.modelID != "GLM-5.3" || len(cap.maas) != 1 || cap.maas[0] != "benefit" {
		t.Fatalf("model=%q model-id=%q maas=%v", cap.model, cap.modelID, cap.maas)
	}
}

func TestStripModelPrefixKeepsUnknownSlashName(t *testing.T) {
	if got := protocol.StripModelPrefix("vendor/unknown-model", "", "nobody"); got != "vendor/unknown-model" {
		t.Fatalf("got %q", got)
	}
	if got := protocol.StripModelPrefix("GLM-5.3", "codearts", ""); got != "GLM-5.3" {
		t.Fatalf("got %q", got)
	}
	if got := protocol.StripModelPrefix("codearts/GLM-5.3", "/codearts/", ""); got != "GLM-5.3" {
		t.Fatalf("got %q", got)
	}
}

func TestParseAndRefreshKeepHostFields(t *testing.T) {
	resetForTest(t)
	cred := protocol.Credential{Type: protocol.Provider, UserID: "u-keep", AccessKeyID: "AK", SecretAccessKey: "sk", SecurityToken: "st", RefreshToken: "rt"}
	own, _ := protocol.MarshalCredential(cred)
	var m map[string]any
	_ = json.Unmarshal(own, &m)
	m["prefix"] = "codearts"
	m["priority"] = 7
	m["note"] = "prod"
	file, _ := json.Marshal(m)

	req, _ := json.Marshal(map[string]any{"FileName": "codearts-u-keep.json", "RawJSON": file})
	var parsed struct {
		Handled bool
		Auth    struct{ StorageJSON []byte }
	}
	if err := json.Unmarshal(mustResult(t, pluginabi.MethodAuthParse, req), &parsed); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"prefix":"codearts"`, `"priority":7`, `"note":"prod"`, `"access_key_id":"AK"`} {
		if !strings.Contains(string(parsed.Auth.StorageJSON), key) {
			t.Fatalf("parse storage missing %s: %s", key, parsed.Auth.StorageJSON)
		}
	}

	merged, err := protocol.MergeCredential(file, protocol.ApplyRefresh(cred, protocol.TokenResponse{RefreshToken: "rt2"}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(merged), `"prefix":"codearts"`) || !strings.Contains(string(merged), `"refresh_token":"rt2"`) {
		t.Fatalf("merged = %s", merged)
	}
}

// errStreamHost answers do_stream with 401 and no chunks, then the body on
// the first stream_read.
type errStreamHost struct {
	closed []string
	reads  int
}

func (h *errStreamHost) Call(method string, payload []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodHostHTTPDoStream:
		return okEnvelope(map[string]any{"status_code": http.StatusUnauthorized, "stream_id": "hs-err"})
	case pluginabi.MethodHostHTTPStreamRead:
		h.reads++
		return okEnvelope(map[string]any{"payload": []byte(`{"error_msg":"token expired"}`), "done": true})
	case pluginabi.MethodHostHTTPStreamClose:
		var req struct {
			StreamID string `json:"stream_id"`
		}
		_ = json.Unmarshal(payload, &req)
		h.closed = append(h.closed, req.StreamID)
	}
	return okEnvelope(map[string]any{})
}

func TestExecuteStreamErrorClosesHostStream(t *testing.T) {
	resetForTest(t)
	host := &errStreamHost{}
	SetCaller(host)
	env := mustHandle(t, pluginabi.MethodExecutorExecuteStream, executeStreamRequest(t))
	if env.OK || env.Error == nil || env.Error.HTTPStatus != http.StatusUnauthorized {
		t.Fatalf("env = %+v", env)
	}
	if !strings.Contains(env.Error.Message, "token expired") {
		t.Fatalf("message = %q", env.Error.Message)
	}
	if len(host.closed) != 1 || host.closed[0] != "hs-err" {
		t.Fatalf("closed = %v", host.closed)
	}
}
