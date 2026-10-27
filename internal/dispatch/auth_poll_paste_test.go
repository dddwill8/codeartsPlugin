package dispatch

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dddwill8/codeartsPlugin/internal/protocol"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const pollPastePortalSecret = "4246780b5c346fe0d0539f80545238652effd265af12fde05a06bd2e137a4f7e"

func TestPollPasteRedirectURLStaysPending(t *testing.T) {
	stub := &pollPasteStub{}
	beginPollPaste(t, stub)
	start := startPollPasteLogin(t)

	pasted := firstHopCallbackURL(pollPastePortalSecret)
	req, _ := json.Marshal(map[string]any{
		"State":        start.State,
		"redirect_url": pasted,
	})
	resp := pollLogin(t, req)
	if resp.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("status=%q message=%q", resp.Status, resp.Message)
	}
	if stub.tokenHits != 0 {
		t.Fatalf("token endpoint hits=%d body=%s", stub.tokenHits, stub.tokenBody)
	}
	if stub.ticketSecret != pollPastePortalSecret {
		t.Fatalf("ticket secret=%q", stub.ticketSecret)
	}
	code, secret, ok := capturedOf(t, start.State)
	if !ok || code != "" || secret != pollPastePortalSecret {
		t.Fatalf("captured code=%q secret=%q ok=%v", code, secret, ok)
	}

	again, _ := json.Marshal(map[string]any{"State": start.State})
	againResp := pollLogin(t, again)
	if againResp.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("follow-up status=%q message=%q", againResp.Status, againResp.Message)
	}
	if stub.tokenHits != 0 {
		t.Fatalf("follow-up token hits=%d", stub.tokenHits)
	}
	if stub.ticketSecret != pollPastePortalSecret {
		t.Fatalf("follow-up ticket secret=%q", stub.ticketSecret)
	}
}

func TestPollPasteCodeExchanges(t *testing.T) {
	t.Run("callback URL", func(t *testing.T) {
		reqFor := func(state string) map[string]any {
			return map[string]any{
				"State": state,
				"code":  "http://127.0.0.1/oauth/callback?code=paste-code",
			}
		}
		assertPollPasteExchanges(t, "paste-code", reqFor)
	})
	t.Run("metadata code", func(t *testing.T) {
		reqFor := func(state string) map[string]any {
			return map[string]any{
				"State":    state,
				"Metadata": map[string]any{"code": "paste-code"},
			}
		}
		assertPollPasteExchanges(t, "paste-code", reqFor)
	})
}

func TestPollPasteBindsPollStateNotForeignState(t *testing.T) {
	t.Run("older poll state", func(t *testing.T) {
		stub := &pollPasteStub{}
		beginPollPaste(t, stub)
		older := startPollPasteLogin(t)
		newer := startPollPasteLogin(t)
		if older.State == newer.State {
			t.Fatal("login states collided")
		}
		olderVerifier := verifierOf(t, older.State)

		req, _ := json.Marshal(map[string]any{
			"State": older.State,
			"code":  "older-paste-code",
		})
		resp := pollLogin(t, req)
		if resp.Status != pluginapi.AuthLoginStatusSuccess {
			t.Fatalf("status=%q message=%q", resp.Status, resp.Message)
		}
		if stub.tokenHits != 1 || !strings.Contains(stub.tokenBody, "older-paste-code") {
			t.Fatalf("token hits=%d body=%s", stub.tokenHits, stub.tokenBody)
		}
		if stub.verifier != olderVerifier {
			t.Fatalf("verifier=%q older=%q", stub.verifier, olderVerifier)
		}
		if _, _, ok := capturedOf(t, older.State); ok {
			t.Fatal("older session still present after exchange")
		}
		code, secret, ok := capturedOf(t, newer.State)
		if !ok || code != "" || secret != "" {
			t.Fatalf("newer captured code=%q secret=%q ok=%v", code, secret, ok)
		}
	})

	t.Run("foreign state stays on newer", func(t *testing.T) {
		stub := &pollPasteStub{}
		beginPollPaste(t, stub)
		older := startPollPasteLogin(t)
		newer := startPollPasteLogin(t)
		pasted := "http://127.0.0.1/oauth/callback?code=bound-newer&state=" + newer.State
		req, _ := json.Marshal(map[string]any{
			"State":        older.State,
			"redirect_url": pasted,
		})
		resp := pollLogin(t, req)
		if resp.Status != pluginapi.AuthLoginStatusPending {
			t.Fatalf("status=%q message=%q", resp.Status, resp.Message)
		}
		if stub.tokenHits != 0 {
			t.Fatalf("token hits=%d body=%s", stub.tokenHits, stub.tokenBody)
		}
		code, secret, ok := capturedOf(t, older.State)
		if !ok || code != "" || secret != "" {
			t.Fatalf("older captured code=%q secret=%q ok=%v", code, secret, ok)
		}
		code, secret, ok = capturedOf(t, newer.State)
		if !ok || code != "bound-newer" || secret != "" {
			t.Fatalf("newer captured code=%q secret=%q ok=%v", code, secret, ok)
		}
	})
}

func TestPollAuthDirFileCode(t *testing.T) {
	t.Run("Host.AuthDir", func(t *testing.T) {
		assertAuthDirExchanges(t, func(state, dir string) map[string]any {
			return map[string]any{
				"State": state,
				"Host":  map[string]any{"AuthDir": dir},
			}
		})
	})
	t.Run("host.auth_dir", func(t *testing.T) {
		assertAuthDirExchanges(t, func(state, dir string) map[string]any {
			return map[string]any{
				"State": state,
				"host":  map[string]any{"auth_dir": dir},
			}
		})
	})
	t.Run("error with empty code", func(t *testing.T) {
		stub := &pollPasteStub{}
		beginPollPaste(t, stub)
		start := startPollPasteLogin(t)
		dir := t.TempDir()
		writeOAuthFile(t, dir, start.State, `{"code":"","state":"`+start.State+`","error":"access_denied"}`)
		req, _ := json.Marshal(map[string]any{
			"State": start.State,
			"Host":  map[string]any{"AuthDir": dir},
		})
		resp := pollLogin(t, req)
		if resp.Status != pluginapi.AuthLoginStatusPending {
			t.Fatalf("status=%q message=%q", resp.Status, resp.Message)
		}
		if stub.tokenHits != 0 {
			t.Fatalf("token hits=%d body=%s", stub.tokenHits, stub.tokenBody)
		}
		code, _, ok := capturedOf(t, start.State)
		if !ok || code != "" {
			t.Fatalf("captured code=%q ok=%v", code, ok)
		}
	})
	t.Run("mismatched file state", func(t *testing.T) {
		stub := &pollPasteStub{}
		beginPollPaste(t, stub)
		start := startPollPasteLogin(t)
		dir := t.TempDir()
		writeOAuthFile(t, dir, start.State, `{"code":"file-code","state":"someoneelse"}`)
		req, _ := json.Marshal(map[string]any{
			"State": start.State,
			"Host":  map[string]any{"AuthDir": dir},
		})
		resp := pollLogin(t, req)
		if resp.Status != pluginapi.AuthLoginStatusPending {
			t.Fatalf("status=%q message=%q", resp.Status, resp.Message)
		}
		if stub.tokenHits != 0 {
			t.Fatalf("token hits=%d body=%s", stub.tokenHits, stub.tokenBody)
		}
		code, _, ok := capturedOf(t, start.State)
		if !ok || code != "" {
			t.Fatalf("captured code=%q ok=%v", code, ok)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		stub := &pollPasteStub{}
		beginPollPaste(t, stub)
		start := startPollPasteLogin(t)
		req, _ := json.Marshal(map[string]any{
			"State": start.State,
			"Host":  map[string]any{"AuthDir": t.TempDir()},
		})
		resp := pollLogin(t, req)
		if resp.Status != pluginapi.AuthLoginStatusPending {
			t.Fatalf("status=%q message=%q", resp.Status, resp.Message)
		}
		if stub.tokenHits != 0 {
			t.Fatalf("token hits=%d body=%s", stub.tokenHits, stub.tokenBody)
		}
	})
}

func TestPollPasteDiscardsMissingState(t *testing.T) {
	stub := &pollPasteStub{}
	beginPollPaste(t, stub)
	start := startPollPasteLogin(t)
	pasted := "http://127.0.0.1/oauth/callback?code=should-drop&state=missing-state"
	req, _ := json.Marshal(map[string]any{
		"State":        start.State,
		"redirect_url": pasted,
	})
	resp := pollLogin(t, req)
	if resp.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("status=%q message=%q", resp.Status, resp.Message)
	}
	if stub.tokenHits != 0 {
		t.Fatalf("token hits=%d body=%s", stub.tokenHits, stub.tokenBody)
	}
	code, secret, ok := capturedOf(t, start.State)
	if !ok || code != "" || secret != "" {
		t.Fatalf("sole session captured code=%q secret=%q ok=%v", code, secret, ok)
	}
}

func assertPollPasteExchanges(t *testing.T, wantCode string, reqFor func(state string) map[string]any) {
	t.Helper()
	stub := &pollPasteStub{}
	beginPollPaste(t, stub)
	start := startPollPasteLogin(t)
	req, _ := json.Marshal(reqFor(start.State))
	resp := pollLogin(t, req)
	if resp.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("status=%q message=%q", resp.Status, resp.Message)
	}
	if stub.tokenHits != 1 || !strings.Contains(stub.tokenBody, wantCode) {
		t.Fatalf("token hits=%d body=%s", stub.tokenHits, stub.tokenBody)
	}
	if stub.code != wantCode {
		t.Fatalf("form code=%q", stub.code)
	}
}

func assertAuthDirExchanges(t *testing.T, reqFor func(state, dir string) map[string]any) {
	t.Helper()
	stub := &pollPasteStub{}
	beginPollPaste(t, stub)
	start := startPollPasteLogin(t)
	dir := t.TempDir()
	writeOAuthFile(t, dir, start.State, `{"code":"file-code","state":"`+start.State+`"}`)
	req, _ := json.Marshal(reqFor(start.State, dir))
	resp := pollLogin(t, req)
	if resp.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("status=%q message=%q", resp.Status, resp.Message)
	}
	if stub.tokenHits != 1 || !strings.Contains(stub.tokenBody, "file-code") {
		t.Fatalf("token hits=%d body=%s", stub.tokenHits, stub.tokenBody)
	}
}

func beginPollPaste(t *testing.T, h http.Handler) {
	t.Helper()
	resetForTest(t)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	SetEndpoints(endpointOverride{SnapManager: srv.URL, STSHost: srv.URL})
	SetHTTPClient(srv.Client())
	regReq, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("oauth_callback_port: 0\n")})
	_ = mustResult(t, pluginabi.MethodPluginRegister, regReq)
}

func startPollPasteLogin(t *testing.T) pluginapi.AuthLoginStartResponse {
	t.Helper()
	raw := mustResult(t, pluginabi.MethodAuthLoginStart, nil)
	var start pluginapi.AuthLoginStartResponse
	if err := json.Unmarshal(raw, &start); err != nil {
		t.Fatal(err)
	}
	if start.State == "" {
		t.Fatal("missing login state")
	}
	listenMu.Lock()
	started := listener != nil
	listenMu.Unlock()
	if started {
		t.Fatal("callback listener must not start when oauth_callback_port is 0")
	}
	return start
}

func pollLogin(t *testing.T, request []byte) pluginapi.AuthLoginPollResponse {
	t.Helper()
	raw, err := Handle(pluginabi.MethodAuthLoginPoll, request)
	if err != nil {
		t.Fatalf("auth.login.poll: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v\n%s", err, raw)
	}
	if !env.OK {
		msg := ""
		if env.Error != nil {
			msg = env.Error.Code + ": " + env.Error.Message
		}
		t.Fatalf("auth.login.poll not ok: %s", msg)
	}
	var resp pluginapi.AuthLoginPollResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func firstHopCallbackURL(secret string) string {
	redirect := "https://codearts.huaweicloud.com/portal/login?theme=light&locale=zh-cn&authorizationAvailable=false&secret=" + secret
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("redirect", redirect)
	return "http://127.0.0.1/oauth/callback?" + q.Encode()
}

func writeOAuthFile(t *testing.T, dir, state, body string) {
	t.Helper()
	path := filepath.Join(dir, ".oauth-codearts-"+state+".oauth")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func verifierOf(t *testing.T, id string) string {
	t.Helper()
	sessMu.Lock()
	defer sessMu.Unlock()
	s := sessions[id]
	if s == nil || s.Verifier == "" {
		t.Fatalf("missing verifier for %s", id)
	}
	return s.Verifier
}

func capturedOf(t *testing.T, id string) (code, secret string, ok bool) {
	t.Helper()
	sessMu.Lock()
	defer sessMu.Unlock()
	s := sessions[id]
	if s == nil {
		return "", "", false
	}
	return s.CapturedCode, s.CapturedSecret, true
}

type pollPasteStub struct {
	tokenHits    int
	ticketSecret string
	tokenBody    string
	code         string
	verifier     string
}

func (s *pollPasteStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, protocol.EpLoginTicket) {
		s.ticketSecret = r.URL.Query().Get("secret")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user_id":"","refresh_token":"","credentials":{}}`))
		return
	}
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, protocol.EpOAuthTokens) {
		s.tokenHits++
		body, _ := io.ReadAll(r.Body)
		s.tokenBody = string(body)
		form, _ := url.ParseQuery(s.tokenBody)
		s.code = form.Get("code")
		s.verifier = form.Get("code_verifier")
		if form.Get("grant_type") != "authorization_code" || form.Get("code") == "" || form.Get("code_verifier") == "" || r.Header.Get("DPoP") == "" {
			http.Error(w, "bad authorization_code form "+s.tokenBody, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user_id":"u-paste","user_name":"paste","refresh_token":"rt-paste","credentials":{"access_key_id":"AKPASTE","secret_access_key":"skpaste","security_token":"st-paste","expiration":"2026-12-01T00:00:00Z"}}`))
		return
	}
	http.NotFound(w, r)
}
