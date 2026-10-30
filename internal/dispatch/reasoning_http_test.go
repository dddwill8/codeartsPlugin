package dispatch

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/dddwill8/codeartsPlugin/internal/protocol"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestReasoningRouteSavesOnAuthFile(t *testing.T) {
	resetForTest(t)
	host := &operatorHost{files: map[string]operatorFile{
		"1": {name: "codearts-user.json", raw: []byte(`{"type":"codearts","user_id":"user","access_key_id":"AK","secret_access_key":"sk","security_token":"st","prefix":"codearts","excluded_models":["glm-5.2"]}`)},
	}}
	SetCaller(host)
	status, _, body := callManagement(t, pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   managementReasoningFull,
	})
	if status != http.StatusOK || !strings.Contains(string(body), `"passthrough":true`) || !strings.Contains(string(body), `"minimal":"low"`) {
		t.Fatalf("status=%d body=%s", status, body)
	}
	save := []byte(`{"passthrough":false,"routes":{"glm-5.3":{"minimal":"drop","low":"keep"}}}`)
	status, _, body = callManagement(t, pluginapi.ManagementRequest{
		Method: http.MethodPost,
		Path:   managementReasoningFull,
		Body:   save,
	})
	if status != http.StatusOK || !strings.Contains(string(body), "已保存") {
		t.Fatalf("save status=%d body=%s", status, body)
	}
	if !strings.Contains(string(host.saved), `"passthrough":false`) || !strings.Contains(string(host.saved), `"prefix":"codearts"`) || strings.Contains(string(host.saved), `"low"`) {
		t.Fatalf("saved = %s", host.saved)
	}
	var stored map[string]json.RawMessage
	if json.Unmarshal(host.saved, &stored) != nil {
		t.Fatalf("saved json: %s", host.saved)
	}
	policy := protocol.ReasoningPolicyFromAuth(host.saved)
	got := protocol.ApplyReasoningPolicy([]byte(`{"reasoning_effort":"minimal"}`), "glm-5.3", policy)
	if strings.Contains(string(got), "reasoning_effort") {
		t.Fatalf("minimal was not dropped: %s", got)
	}
}

func TestManagementPageKeepsCompactLoginAndRoute(t *testing.T) {
	resetForTest(t)
	status, _, body := callManagement(t, pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   resourceCallbackFull,
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	htmlBody := string(body)
	for _, want := range []string{"开启推理强度透传", "刷新模型", "保存路由", "未列出的强度", "不要把这条 URL 贴进 CPA 的 OAuth 回调框"} {
		if !strings.Contains(htmlBody, want) {
			t.Fatalf("page missing %s", want)
		}
	}
}
