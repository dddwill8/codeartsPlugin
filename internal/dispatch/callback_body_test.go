package dispatch

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestOAuthCallbackBodySecret(t *testing.T) {
	resetForTest(t)
	ticketSecret := ""
	tokenHits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/v1/login/ticket") {
			ticketSecret = r.URL.Query().Get("secret")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user_id":"","refresh_token":"","credentials":{}}`))
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/oauth2/tokens") {
			tokenHits++
			http.Error(w, "token endpoint must not run on a body-only secret", http.StatusBadRequest)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	SetEndpoints(endpointOverride{SnapManager: srv.URL, STSHost: srv.URL})
	SetHTTPClient(srv.Client())

	regReq, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("oauth_callback_port: 0\n")})
	_ = mustResult(t, pluginabi.MethodPluginRegister, regReq)
	startRaw := mustResult(t, pluginabi.MethodAuthLoginStart, nil)
	var start pluginapi.AuthLoginStartResponse
	if err := json.Unmarshal(startRaw, &start); err != nil {
		t.Fatal(err)
	}
	if start.State == "" {
		t.Fatal("missing login state")
	}

	const body = "secret=abc&redirect=https%3A%2F%2Fcodearts.huaweicloud.com%2Fportal%2Flogin"
	req := httptest.NewRequest(http.MethodPost, "/oauth/callback", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handleOAuthCallbackHTTP(rec, req)
	html := rec.Body.String()
	if strings.Contains(html, "登录失败") {
		t.Fatalf("callback page says login failed:\n%s", html)
	}

	pollReq, _ := json.Marshal(map[string]any{"State": start.State})
	pollRaw := mustResult(t, pluginabi.MethodAuthLoginPoll, pollReq)
	var poll pluginapi.AuthLoginPollResponse
	if err := json.Unmarshal(pollRaw, &poll); err != nil {
		t.Fatal(err)
	}
	if poll.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("poll status = %q message=%q", poll.Status, poll.Message)
	}
	if tokenHits != 0 {
		t.Fatalf("token endpoint called, hits=%d", tokenHits)
	}
	if ticketSecret != "abc" {
		t.Fatalf("ticket poll secret = %q", ticketSecret)
	}
}
