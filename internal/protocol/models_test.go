package protocol

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoverModelsUsesRegisteredAgentModelID(t *testing.T) {
	const (
		display    = "DeepSeek-V4.1-Flash-1017"
		registered = "deepseek-v4.1-flash"
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, EpAgentList):
			_, _ = w.Write([]byte(`{"agents":[{"agent_id":"agent-1","agent_name":"CodeAgent","is_primary_agent":true,"show_in_ide":true,"alias":{"alias_zh_cn":"智能体"}}]}`))
		case strings.Contains(r.URL.Path, EpAgentDetail):
			_, _ = w.Write([]byte(`{"gpts":{"models":[{
				"model_name":"` + display + `",
				"model_id":"` + display + `",
				"model_alias":"` + display + `",
				"model_parameters":{"model_id":"` + registered + `","context_window":1000000,"max_tokens":8192}
			}]}}`))
		case strings.Contains(r.URL.Path, EpModelBuiltin):
			_, _ = w.Write([]byte(`{"builtinModels":[]}`))
		default:
			_, _ = w.Write([]byte(`{"error_code":"0000","result":{"models":[]}}`))
		}
	}))
	defer srv.Close()

	accountID := "discover-registered-id"
	t.Cleanup(func() {
		catalog.Lock()
		delete(catalog.accounts, accountID)
		catalog.Unlock()
	})

	infos := DiscoverModels(srv.Client(), SignCredential{}, accountID, srv.URL, srv.URL, false)
	if len(infos) != 1 || infos[0].ID != registered {
		t.Fatalf("models = %+v, want id %s", infos, registered)
	}
	if infos[0].MaxTokens != 8192 {
		t.Fatalf("max tokens = %d", infos[0].MaxTokens)
	}
}
