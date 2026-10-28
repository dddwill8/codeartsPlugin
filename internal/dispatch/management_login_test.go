package dispatch

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dddwill8/codeartsPlugin/internal/protocol"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestPageLoginPasteExchangesWithoutCPAMPCard(t *testing.T) {
	stub := &pollPasteStub{}
	beginPollPaste(t, stub)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	started := startPageLogin(t)
	if strings.Contains(logs.String(), started.AuthURL) || strings.Contains(logs.String(), "code_challenge=") {
		t.Fatalf("log printed the authorize URL: %s", logs.String())
	}
	sessMu.Lock()
	n := len(sessions)
	sessMu.Unlock()
	if n != 1 {
		t.Fatalf("sessions=%d", n)
	}

	const code = "page-only-code"
	rawURL := "http://127.0.0.1:18080/oauth/callback?code=" + code + "&state=huawei-page"
	status, result, body := submitCallback(t, rawURL)
	if status != http.StatusOK || !result.Done || !result.Stored || result.Label != "paste" {
		t.Fatalf("status=%d result=%+v", status, result)
	}
	if stub.tokenHits != 1 || stub.code != code {
		t.Fatalf("hits=%d code=%q", stub.tokenHits, stub.code)
	}
	if strings.Contains(string(body), code) || strings.Contains(string(body), "rt-paste") || strings.Contains(logs.String(), code) || strings.Contains(logs.String(), "rt-paste") {
		t.Fatalf("leaked callback\nbody=%s\nlog=%s", body, logs.String())
	}
	if _, _, ok := capturedOf(t, started.State); ok {
		t.Fatal("session remained")
	}
	term, ok := terminalOf(started.State)
	if !ok || !term.OK || term.Label != "paste" {
		t.Fatalf("terminal=%+v ok=%v", term, ok)
	}

	againBody := mustJSON(t, map[string]string{
		"url":         rawURL,
		"login_state": started.State,
	})
	againStatus, again, _ := callManagement(t, pluginapi.ManagementRequest{
		Method:  http.MethodPost,
		Path:    managementCallbackFull,
		Headers: managementHeaders("test-mgmt"),
		Body:    againBody,
	})
	if againStatus != http.StatusOK || !again.Done || again.Stored || again.Label != "paste" || stub.tokenHits != 1 {
		t.Fatalf("repeat status=%d result=%+v hits=%d", againStatus, again, stub.tokenHits)
	}
	if !strings.Contains(again.Message, "登录完成") {
		t.Fatalf("repeat message=%q", again.Message)
	}
	manual := "http://127.0.0.1:18080/oauth/callback?code=" + code + "&state=" + url.QueryEscape(started.State)
	manualStatus, manualResult, _ := submitCallback(t, manual)
	if manualStatus != http.StatusOK || !manualResult.Done || manualResult.Stored || manualResult.Label != "paste" || stub.tokenHits != 1 {
		t.Fatalf("manual status=%d result=%+v hits=%d", manualStatus, manualResult, stub.tokenHits)
	}
	next := startPageLogin(t)
	oldStatus, oldResult, _ := submitCallback(t, manual)
	if oldStatus != http.StatusOK || !oldResult.Done || oldResult.Stored || stub.tokenHits != 1 {
		t.Fatalf("old state status=%d result=%+v hits=%d", oldStatus, oldResult, stub.tokenHits)
	}
	if got, _, ok := capturedOf(t, next.State); !ok || got != "" {
		t.Fatalf("new session captured %q ok=%v", got, ok)
	}
	poll := pollLogin(t, mustJSON(t, map[string]any{"State": started.State}))
	if poll.Status != pluginapi.AuthLoginStatusError || stub.tokenHits != 1 {
		t.Fatalf("poll status=%q hits=%d", poll.Status, stub.tokenHits)
	}
}

func TestPageStatusExchangesCodeCapturedByListener(t *testing.T) {
	stub := &pollPasteStub{}
	beginPollPaste(t, stub)
	started := startPageLogin(t)
	const code = "listener-code"
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code="+code+"&state=huawei-listener", nil)
	rec := httptest.NewRecorder()
	handleOAuthCallbackHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("listener status=%d", rec.Code)
	}
	if stub.tokenHits != 0 {
		t.Fatalf("listener exchanged, hits=%d", stub.tokenHits)
	}
	got, _, ok := capturedOf(t, started.State)
	if !ok || got != code {
		t.Fatalf("captured=%q ok=%v", got, ok)
	}

	status, result, body := queryPageLogin(t, started.State)
	if status != http.StatusOK || !result.Done || result.Label != "paste" {
		t.Fatalf("status=%d result=%+v body=%s", status, result, body)
	}
	if stub.tokenHits != 1 || stub.code != code {
		t.Fatalf("hits=%d code=%q", stub.tokenHits, stub.code)
	}
	if strings.Contains(string(body), code) || strings.Contains(string(body), "rt-paste") || strings.Contains(string(body), "st-paste") {
		t.Fatalf("status leaked secrets: %s", body)
	}
	if _, _, ok := capturedOf(t, started.State); ok {
		t.Fatal("session remained")
	}

	againStatus, again, _ := queryPageLogin(t, started.State)
	if againStatus != http.StatusOK || !again.Done || stub.tokenHits != 1 {
		t.Fatalf("second status=%d result=%+v hits=%d", againStatus, again, stub.tokenHits)
	}
	poll := pollLogin(t, mustJSON(t, map[string]any{"State": started.State}))
	if poll.Status == pluginapi.AuthLoginStatusSuccess || stub.tokenHits != 1 {
		t.Fatalf("poll status=%q hits=%d", poll.Status, stub.tokenHits)
	}
}

func TestPageLoginSaveFailureIsNotDone(t *testing.T) {
	stub := &pollPasteStub{}
	beginPollPaste(t, stub)
	host := &loginHost{failSave: true}
	SetCaller(host)
	started := startPageLogin(t)
	const code = "save-fail-code"
	rawURL := "http://127.0.0.1:18080/oauth/callback?code=" + code + "&state=huawei-save"
	status, result, body := submitCallback(t, rawURL)
	if status != http.StatusBadGateway || result.Done || result.OK || !strings.Contains(result.Message, "没有写入") {
		t.Fatalf("status=%d result=%+v body=%s", status, result, body)
	}
	if stub.tokenHits != 1 || stub.code != code {
		t.Fatalf("hits=%d code=%q", stub.tokenHits, stub.code)
	}
	if host.saveCount() != 1 {
		t.Fatalf("save calls=%d", host.saveCount())
	}
	if _, ok := terminalOf(started.State); ok {
		t.Fatal("save failure wrote a success terminal")
	}
	got, _, ok := capturedOf(t, started.State)
	if !ok || got != "" {
		t.Fatalf("session code=%q ok=%v", got, ok)
	}
	if strings.Contains(string(body), code) || strings.Contains(string(body), "rt-paste") {
		t.Fatalf("leaked callback: %s", body)
	}

	againStatus, again, _ := queryPageLogin(t, started.State)
	if againStatus != http.StatusBadGateway || again.Done || !strings.Contains(again.Message, "没有写入") || stub.tokenHits != 1 || host.saveCount() != 1 {
		t.Fatalf("status=%d result=%+v hits=%d saves=%d", againStatus, again, stub.tokenHits, host.saveCount())
	}
	pasteStatus, paste, _ := submitCallback(t, rawURL)
	if pasteStatus != http.StatusBadGateway || paste.Done || paste.Stored || stub.tokenHits != 1 || host.saveCount() != 1 {
		t.Fatalf("paste status=%d result=%+v hits=%d saves=%d", pasteStatus, paste, stub.tokenHits, host.saveCount())
	}
	poll := pollLogin(t, mustJSON(t, map[string]any{"State": started.State}))
	if poll.Status != pluginapi.AuthLoginStatusError || stub.tokenHits != 1 || strings.Contains(poll.Message, "rt-paste") {
		t.Fatalf("poll status=%q message=%q hits=%d", poll.Status, poll.Message, stub.tokenHits)
	}
	if !strings.Contains(poll.Message, "not written") {
		t.Fatalf("poll message=%q", poll.Message)
	}
}

func TestLoginStatusPrefersBusyOverPriorFailure(t *testing.T) {
	stub := &pollPasteStub{}
	beginPollPaste(t, stub)
	started := startPageLogin(t)
	sess := getSession(started.State)
	if sess == nil {
		t.Fatal("missing session")
	}
	sessMu.Lock()
	sess.exchanging = true
	sess.exchangeFailed = true
	sess.CapturedCode = ""
	sessMu.Unlock()

	out := loginStatus(started.State, "")
	if out.Status != http.StatusOK || !out.Pending || out.Done || !strings.Contains(out.Message, "正在换票") {
		t.Fatalf("status=%+v", out)
	}
	if strings.Contains(out.Message, "授权码被拒绝") {
		t.Fatalf("prior failure won: %+v", out)
	}
}

func TestClaimClearsExchangeFailed(t *testing.T) {
	stub := &pollPasteStub{}
	beginPollPaste(t, stub)
	started := startPageLogin(t)
	sess := getSession(started.State)
	if sess == nil {
		t.Fatal("missing session")
	}
	sessMu.Lock()
	sess.CapturedCode = "newer-code"
	sess.exchangeFailed = true
	sess.saveFailed = true
	sessMu.Unlock()

	code, _ := claimCaptured(sess)
	if code != "newer-code" {
		t.Fatalf("code=%q", code)
	}
	if sessionExchangeFailed(sess) || sessionSaveFailed(sess) {
		t.Fatal("previous failure stayed set after claim")
	}
	sessMu.Lock()
	left := sess.CapturedCode
	sess.CapturedCode = "still-here"
	sess.exchangeFailed = false
	sessMu.Unlock()
	if left != "" {
		t.Fatalf("captured left %q", left)
	}
	markExchangeFailedIfNoNewerCode(sess)
	sessMu.Lock()
	failed := sess.exchangeFailed
	leftCode := sess.CapturedCode
	sessMu.Unlock()
	if failed || leftCode != "still-here" {
		t.Fatalf("exchangeFailed=%v captured=%q", failed, leftCode)
	}
}

func TestPageLoginReplacesTheOnlySession(t *testing.T) {
	stub := &pollPasteStub{}
	beginPollPaste(t, stub)
	first := startPageLogin(t)
	if captureCallback("before-replace", "", first.State, "") == nil {
		t.Fatal("capture failed")
	}
	second := startPageLogin(t)
	if first.State == second.State {
		t.Fatal("state was reused")
	}
	sessMu.Lock()
	n := len(sessions)
	_, firstAlive := sessions[first.State]
	secondCode := ""
	if sessions[second.State] != nil {
		secondCode = sessions[second.State].CapturedCode
	}
	sessMu.Unlock()
	if n != 1 || firstAlive || secondCode != "" {
		t.Fatalf("sessions=%d firstAlive=%v secondCode=%q", n, firstAlive, secondCode)
	}
	if stub.tokenHits != 0 {
		t.Fatalf("replace exchanged, hits=%d", stub.tokenHits)
	}
}

func TestPageRoutesRejectMissingCredential(t *testing.T) {
	resetForTest(t)
	regReq, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("oauth_callback_port: 0\n")})
	_ = mustResult(t, pluginabi.MethodPluginRegister, regReq)
	const code = "unauth-page-code"
	for _, path := range []string{managementLoginFull, managementCallbackFull, managementStatusFull} {
		status, result, body := callManagement(t, pluginapi.ManagementRequest{
			Method: http.MethodPost,
			Path:   path,
			Body:   []byte(`{"url":"http://127.0.0.1:18080/oauth/callback?code=` + code + `","state":"sess"}`),
		})
		if status != http.StatusForbidden || result.Stored || result.Done || strings.Contains(string(body), code) {
			t.Fatalf("%s status=%d result=%+v body=%s", path, status, result, body)
		}
	}
	sessMu.Lock()
	n := len(sessions)
	sessMu.Unlock()
	if n != 0 {
		t.Fatalf("unauthenticated routes created sessions=%d", n)
	}
	postStatus, postResult, _ := callManagement(t, pluginapi.ManagementRequest{
		Method:  http.MethodPost,
		Path:    resourceCallbackFull,
		Headers: managementHeaders("test-mgmt"),
		Body:    []byte(`{"url":"http://127.0.0.1:18080/oauth/callback?code=` + code + `"}`),
	})
	if postStatus != http.StatusMethodNotAllowed || postResult.Stored {
		t.Fatalf("resource POST status=%d result=%+v", postStatus, postResult)
	}
}

func TestExpiredLoginDoesNotAcceptItsCodeOnTheNextSession(t *testing.T) {
	stub := &pollPasteStub{}
	beginPollPaste(t, stub)
	first := startPageLogin(t)
	if captureCallback("expired-code", "", first.State, "") == nil {
		t.Fatal("capture failed")
	}
	sessMu.Lock()
	sessions[first.State].ExpiresAt = time.Now().Add(-time.Second)
	sessMu.Unlock()
	second := startPageLogin(t)

	status, result, _ := submitCallback(t, "http://127.0.0.1:18080/oauth/callback?code=expired-code&state="+url.QueryEscape(first.State))
	if status != http.StatusConflict || result.Stored || result.Bound || !strings.Contains(result.Message, "请重新点登录") {
		t.Fatalf("status=%d result=%+v", status, result)
	}
	code, _, ok := capturedOf(t, second.State)
	if !ok || code != "" || stub.tokenHits != 0 {
		t.Fatalf("new session code=%q ok=%v hits=%d", code, ok, stub.tokenHits)
	}

	staleBody, _ := json.Marshal(map[string]string{
		"url":         "http://127.0.0.1:18080/oauth/callback?code=stale-huawei&state=huawei-old",
		"login_state": first.State,
	})
	staleStatus, stale, _ := callManagement(t, pluginapi.ManagementRequest{
		Method:  http.MethodPost,
		Path:    managementCallbackFull,
		Headers: managementHeaders("test-mgmt"),
		Body:    staleBody,
	})
	if staleStatus != http.StatusConflict || stale.Stored || stub.tokenHits != 0 {
		t.Fatalf("stale page state status=%d result=%+v hits=%d", staleStatus, stale, stub.tokenHits)
	}
	code, _, ok = capturedOf(t, second.State)
	if !ok || code != "" {
		t.Fatalf("stale paste wrote code=%q", code)
	}

	_, cleared, _ := queryPageLogin(t, first.State)
	if cleared.Done || !strings.Contains(cleared.Message, "请重新点登录") {
		t.Fatalf("expired status=%+v", cleared)
	}
	sessMu.Lock()
	n := len(sessions)
	sessMu.Unlock()
	if n != 1 {
		t.Fatalf("status created sessions=%d", n)
	}
}

func TestPasteWithoutLoginDoesNotCreateSession(t *testing.T) {
	stub := &pollPasteStub{}
	beginPollPaste(t, stub)
	_ = startPageLogin(t)
	clearLoginState()
	status, result, _ := submitCallback(t, "http://127.0.0.1:18080/oauth/callback?code=after-restart&state=huawei-restart")
	if status != http.StatusConflict || result.Bound || result.Stored || stub.tokenHits != 0 {
		t.Fatalf("status=%d result=%+v hits=%d", status, result, stub.tokenHits)
	}
	sessMu.Lock()
	n := len(sessions)
	sessMu.Unlock()
	if n != 0 {
		t.Fatalf("sessions=%d", n)
	}
	emptyStatus, empty, _ := queryPageLogin(t, "anything")
	if emptyStatus != http.StatusOK || empty.Done || !strings.Contains(empty.Message, "请重新点登录") {
		t.Fatalf("status query=%d result=%+v", emptyStatus, empty)
	}
	if nSessions() != 0 {
		t.Fatal("status query created a session")
	}
}

func TestManagementExchangeReadsHostCallbackID(t *testing.T) {
	t.Run("uses host callback", func(t *testing.T) {
		resetForTest(t)
		direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("direct dial %s %s", r.Method, r.URL.String())
		}))
		t.Cleanup(direct.Close)
		SetHTTPClient(direct.Client())
		host := &loginHost{}
		SetCaller(host)
		regReq, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("oauth_callback_port: 0\n")})
		_ = mustResult(t, pluginabi.MethodPluginRegister, regReq)
		var logs bytes.Buffer
		log.SetOutput(&logs)
		t.Cleanup(func() { log.SetOutput(os.Stderr) })

		started := startPageLoginExtra(t, map[string]any{"host_callback_id": "cb-page"})
		const code = "callback-id-code"
		status, result, body := submitCallbackExtra(t, "http://127.0.0.1:18080/oauth/callback?code="+code+"&state=huawei", map[string]any{"host_callback_id": "cb-page"})
		if status != http.StatusOK || !result.Done || result.Label != "host-user" {
			t.Fatalf("status=%d result=%+v body=%s", status, result, body)
		}
		if !host.sawHTTPDo("cb-page") {
			t.Fatalf("host calls=%+v", host.snapshot())
		}
		if !host.saved("codearts-u-host.json") {
			t.Fatalf("saves=%+v", host.snapshot())
		}
		if strings.Contains(logs.String(), code) || strings.Contains(logs.String(), "rt-host") || strings.Contains(string(body), "rt-host") || strings.Contains(started.AuthURL, code) {
			t.Fatalf("leaked secrets\nlog=%s\nbody=%s", logs.String(), body)
		}
	})

	t.Run("direct dial without callback id", func(t *testing.T) {
		stub := &pollPasteStub{}
		beginPollPaste(t, stub)
		host := &loginHost{}
		SetCaller(host)
		_ = startPageLogin(t)
		status, result, _ := submitCallback(t, "http://127.0.0.1:18080/oauth/callback?code=direct-code&state=huawei")
		if status != http.StatusOK || !result.Done {
			t.Fatalf("status=%d result=%+v", status, result)
		}
		if stub.tokenHits != 1 || stub.code != "direct-code" {
			t.Fatalf("direct hits=%d code=%q", stub.tokenHits, stub.code)
		}
		if host.sawHTTPDo("") || host.httpDoCount() != 0 {
			t.Fatalf("host HTTP was used: %+v", host.snapshot())
		}
		if !host.saved("codearts-u-paste.json") {
			t.Fatalf("auth was not saved via host.auth.save: %+v", host.snapshot())
		}
	})
}

func startPageLogin(t *testing.T) managementResult {
	t.Helper()
	return startPageLoginExtra(t, nil)
}

func startPageLoginExtra(t *testing.T, extra map[string]any) managementResult {
	t.Helper()
	status, result, body := callManagementExtra(t, pluginapi.ManagementRequest{
		Method:  http.MethodPost,
		Path:    managementLoginFull,
		Headers: managementHeaders("test-mgmt"),
		Body:    []byte(`{}`),
	}, extra)
	if status != http.StatusOK || !result.OK || result.State == "" || !strings.Contains(result.AuthURL, "/authorize?") {
		t.Fatalf("start status=%d result=%+v body=%s", status, result, body)
	}
	return result
}

func queryPageLogin(t *testing.T, state string) (int, managementResult, []byte) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"state": state})
	if err != nil {
		t.Fatal(err)
	}
	return callManagement(t, pluginapi.ManagementRequest{
		Method:  http.MethodPost,
		Path:    managementStatusFull,
		Headers: managementHeaders("test-mgmt"),
		Body:    body,
	})
}

func submitCallbackExtra(t *testing.T, raw string, extra map[string]any) (int, managementResult, []byte) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"url": raw})
	if err != nil {
		t.Fatal(err)
	}
	return callManagementExtra(t, pluginapi.ManagementRequest{
		Method:  http.MethodPost,
		Path:    managementCallbackFull,
		Headers: managementHeaders("test-mgmt"),
		Body:    body,
	}, extra)
}

func callManagementExtra(t *testing.T, req pluginapi.ManagementRequest, extra map[string]any) (int, managementResult, []byte) {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(extra) > 0 {
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		for k, v := range extra {
			m[k] = v
		}
		raw, err = json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
	}
	env := mustHandle(t, pluginabi.MethodManagementHandle, raw)
	if !env.OK {
		msg := ""
		if env.Error != nil {
			msg = env.Error.Code + ": " + env.Error.Message
		}
		t.Fatalf("management.handle not ok: %s", msg)
	}
	var resp pluginapi.ManagementResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatal(err)
	}
	status := resp.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	var result managementResult
	if len(resp.Body) > 0 && resp.Body[0] == '{' {
		if err := json.Unmarshal(resp.Body, &result); err != nil {
			t.Fatal(err)
		}
	}
	return status, result, resp.Body
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func nSessions() int {
	sessMu.Lock()
	defer sessMu.Unlock()
	return len(sessions)
}

type loginHostCall struct {
	method     string
	callbackID string
	name       string
}

type loginHost struct {
	mu       sync.Mutex
	calls    []loginHostCall
	failSave bool
}

func (h *loginHost) Call(method string, payload []byte) ([]byte, error) {
	rec := loginHostCall{method: method}
	var body []byte
	switch method {
	case pluginabi.MethodHostHTTPDo:
		var p struct {
			CallbackID string `json:"host_callback_id"`
			URL        string `json:"url"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		rec.callbackID = p.CallbackID
		body = []byte(`{}`)
		if strings.Contains(p.URL, protocol.EpOAuthTokens) {
			body = []byte(`{"user_id":"u-host","user_name":"host-user","refresh_token":"rt-host","credentials":{"access_key_id":"AKHOST","secret_access_key":"sk","security_token":"st","expiration":"2026-12-01T00:00:00Z"}}`)
		}
	case pluginabi.MethodHostAuthSave:
		var req pluginapi.HostAuthSaveRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, err
		}
		rec.name = req.Name
		h.mu.Lock()
		h.calls = append(h.calls, rec)
		fail := h.failSave
		h.mu.Unlock()
		if fail {
			return json.Marshal(envelope{OK: false, Error: &envelopeError{Code: "save_error", Message: "auth dir missing"}})
		}
		body = []byte(`{"name":"` + req.Name + `"}`)
	default:
		body = []byte(`{}`)
	}
	if method != pluginabi.MethodHostAuthSave {
		h.mu.Lock()
		h.calls = append(h.calls, rec)
		h.mu.Unlock()
	}
	result, err := json.Marshal(struct {
		StatusCode int    `json:"StatusCode"`
		Body       []byte `json:"Body"`
	}{StatusCode: http.StatusOK, Body: body})
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: result})
}

func (h *loginHost) snapshot() []loginHostCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]loginHostCall, len(h.calls))
	copy(out, h.calls)
	return out
}

func (h *loginHost) sawHTTPDo(id string) bool {
	for _, call := range h.snapshot() {
		if call.method == pluginabi.MethodHostHTTPDo && call.callbackID == id {
			return true
		}
	}
	return false
}

func (h *loginHost) httpDoCount() int {
	n := 0
	for _, call := range h.snapshot() {
		if call.method == pluginabi.MethodHostHTTPDo {
			n++
		}
	}
	return n
}

func (h *loginHost) saved(name string) bool {
	for _, call := range h.snapshot() {
		if call.method == pluginabi.MethodHostAuthSave && call.name == name {
			return true
		}
	}
	return false
}

func (h *loginHost) saveCount() int {
	n := 0
	for _, call := range h.snapshot() {
		if call.method == pluginabi.MethodHostAuthSave {
			n++
		}
	}
	return n
}
