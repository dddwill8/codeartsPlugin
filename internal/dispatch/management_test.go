package dispatch

import (
	"bytes"
	"encoding/json"
	"io"
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

func TestManagementPageDoesNotCaptureQuery(t *testing.T) {
	resetForTest(t)
	const leaked = "page-query-code-must-not-bind"
	start := startBareLogin(t)
	req := pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   resourceCallbackFull,
		Query:  url.Values{"code": []string{leaked}, "url": []string{"http://127.0.0.1:18080/oauth/callback?code=" + leaked}},
	}
	status, _, body := callManagement(t, req)
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	htmlBody := string(body)
	for _, want := range []string{managementMenuName, "登录", "地址栏里的完整 URL", "不要把这条 URL 贴进 CPA 的 OAuth 回调框", "不需要打开 CPAMP", "http://127.0.0.1:18080/oauth/callback", "刷新后会接着查同一次登录", "window.open", "login_state"} {
		if !strings.Contains(htmlBody, want) {
			t.Fatalf("page missing %s", want)
		}
	}
	if strings.Contains(htmlBody, leaked) {
		t.Fatal("resource page reflected the query code")
	}
	script := htmlBody[strings.Index(htmlBody, "<script>"):]
	for _, want := range []string{
		"function keepURL(data)",
		"data.stored !== true",
		"data.pending === true",
		"data.continue_url",
		"function portalContinueURL(url)",
		"parsed.protocol !== 'https:'",
		"codearts.huaweicloud.com",
		".huaweicloud.com",
		"继续华为授权",
		`link.target = '_blank'`,
		"noopener noreferrer",
		"createElement('a')",
		"link.textContent",
		"let pollGen = 0",
		"pollAbort.abort()",
		"gen !== pollGen",
		"state !== loginState",
		"new AbortController()",
		"signal: abort.signal",
		"pollGen++",
		"codearts.loginState",
		"function savedLoginState()",
		"function rememberLoginState(",
		"function resumeLogin()",
		"if (loginState) resumeLogin();",
		"loginPhase !== 'terminal'",
		"登录仍在进行",
		"function finishedLogin(",
		"return !!(data && data.done === true);",
		"function forgetLogin()",
		"if (noLogin(snapshot.data)) forgetLogin();",
		"没能查询这次登录的状态",
		"popup.close()",
		"saved.phase === 'terminal'",
		"saved.phase === 'pending'",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("page script missing %s", want)
		}
	}
	resumeAt := strings.Index(script, "function resumeLogin()")
	clickAt := strings.Index(script, "loginButton.addEventListener")
	if resumeAt < 0 || clickAt < resumeAt {
		t.Fatal("resumeLogin is not defined before the login button")
	}
	resumeBody := script[resumeAt:clickAt]
	if strings.Contains(resumeBody, "cfg.start") {
		t.Fatal("resumeLogin starts a new session")
	}
	if !strings.Contains(resumeBody, "refreshSaved") {
		t.Fatal("resumeLogin does not query the saved session")
	}
	formAt := strings.Index(script, "form.addEventListener")
	if clickAt < 0 || formAt < clickAt {
		t.Fatal("login click handler is missing")
	}
	clickBody := script[clickAt:formAt]
	openAt := strings.Index(clickBody, "window.open")
	awaitAt := strings.Index(clickBody, "await ")
	if openAt < 0 || awaitAt < 0 || openAt > awaitAt {
		t.Fatal("window.open runs after an await")
	}
	stayAt := strings.Index(clickBody, "finishedLogin")
	startAt := strings.Index(clickBody, "cfg.start")
	if stayAt < 0 || startAt < 0 || stayAt > startAt {
		t.Fatal("oauth-start is not after the finished-login check")
	}
	if !strings.Contains(clickBody[stayAt:startAt], "return;") {
		t.Fatal("a finished login still reaches oauth-start")
	}
	if strings.Contains(script, "innerHTML") {
		t.Fatal("page script assigns innerHTML")
	}
	if strings.Contains(htmlBody, "等待插件认证中") {
		t.Fatal("page still requires the CPAMP card")
	}
	code, secret, ok := capturedOf(t, start.State)
	if !ok || code != "" || secret != "" {
		t.Fatalf("captured code=%q secret=%q ok=%v", code, secret, ok)
	}
	postStatus, postResult, postBody := callManagement(t, pluginapi.ManagementRequest{
		Method:  http.MethodPost,
		Path:    resourceCallbackFull,
		Headers: managementHeaders("test-mgmt"),
		Body:    []byte(`{"url":"http://127.0.0.1:18080/oauth/callback?code=` + leaked + `"}`),
	})
	if postStatus != http.StatusMethodNotAllowed {
		t.Fatalf("resource POST status=%d body=%s", postStatus, postBody)
	}
	if strings.Contains(string(postBody), leaked) || postResult.Stored {
		t.Fatalf("resource POST stored a code: %+v %s", postResult, postBody)
	}
	code, _, ok = capturedOf(t, start.State)
	if !ok || code != "" {
		t.Fatalf("captured after resource POST code=%q", code)
	}
}

func TestManagementPageAcceptsFilenamePluginID(t *testing.T) {
	resetForTest(t)
	const leaked = "filename-id-must-not-bind"
	start := startBareLogin(t)
	for _, id := range []string{"codearts-linux-amd64", "codearts-linux-arm64"} {
		pagePath := "/v0/resource/plugins/" + id + "/callback"
		status, _, body := callManagement(t, pluginapi.ManagementRequest{
			Method: http.MethodGet,
			Path:   pagePath + "/",
			Query:  url.Values{"code": []string{leaked}},
		})
		if status != http.StatusOK || !strings.Contains(string(body), managementMenuName) || strings.Contains(string(body), leaked) {
			t.Fatalf("%s status=%d body leaked=%t", id, status, strings.Contains(string(body), leaked))
		}
		postStatus, postResult, postBody := callManagement(t, pluginapi.ManagementRequest{
			Method:  http.MethodPost,
			Path:    pagePath,
			Headers: managementHeaders("test-mgmt"),
			Body:    []byte(`{"url":"http://127.0.0.1:18080/oauth/callback?code=` + leaked + `"}`),
		})
		if postStatus != http.StatusMethodNotAllowed || postResult.Stored || strings.Contains(string(postBody), leaked) {
			t.Fatalf("%s POST status=%d result=%+v body=%s", id, postStatus, postResult, postBody)
		}
	}
	code, _, ok := capturedOf(t, start.State)
	if !ok || code != "" {
		t.Fatalf("captured=%q ok=%v", code, ok)
	}
	for _, path := range []string{
		"/v0/resource/plugins/codearts-linux-amd64/other",
		"/v0/resource/plugins/../callback",
		"/v0/resource/plugins/callback",
	} {
		status, _, _ := callManagement(t, pluginapi.ManagementRequest{Method: http.MethodGet, Path: path})
		if status != http.StatusNotFound {
			t.Fatalf("%s status=%d", path, status)
		}
	}

	const custom = "/assigned/codearts-linux-amd64"
	status, _, _ := callManagement(t, pluginapi.ManagementRequest{Method: http.MethodGet, Path: custom + "/callback"})
	if status != http.StatusNotFound {
		t.Fatalf("custom base matched before register, status=%d", status)
	}
	reg, err := json.Marshal(pluginapi.ManagementRegistrationRequest{ResourceBasePath: custom})
	if err != nil {
		t.Fatal(err)
	}
	if env := mustHandle(t, pluginabi.MethodManagementRegister, reg); !env.OK {
		t.Fatal("management.register failed")
	}
	status, _, body := callManagement(t, pluginapi.ManagementRequest{Method: http.MethodGet, Path: custom + "/callback"})
	if status != http.StatusOK || !strings.Contains(string(body), managementMenuName) {
		t.Fatalf("registered base status=%d", status)
	}
	_ = mustResult(t, pluginabi.MethodManagementRegister, nil)
	status, _, _ = callManagement(t, pluginapi.ManagementRequest{Method: http.MethodGet, Path: custom + "/callback"})
	if status != http.StatusOK {
		t.Fatalf("empty register cleared the resource base, status=%d", status)
	}
	status, _, _ = callManagement(t, pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   "/v0/resource/plugins/codearts-linux-arm64/callback",
	})
	if status != http.StatusOK {
		t.Fatalf("release id after register status=%d", status)
	}
}

func TestManagementPostRejectsMissingCredential(t *testing.T) {
	resetForTest(t)
	start := startBareLogin(t)
	const code = "unauth-code-must-not-bind"
	status, result, body := callManagement(t, pluginapi.ManagementRequest{
		Method: http.MethodPost,
		Path:   managementCallbackFull,
		Body:   []byte(`{"url":"http://127.0.0.1:18080/oauth/callback?code=` + code + `"}`),
	})
	if status != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", status, body)
	}
	if result.Stored || result.Bound || strings.Contains(string(body), code) {
		t.Fatalf("unauthenticated post stored a code: %+v %s", result, body)
	}
	got, _, ok := capturedOf(t, start.State)
	if !ok || got != "" {
		t.Fatalf("captured=%q ok=%v", got, ok)
	}
	for _, header := range []http.Header{
		{"Authorization": []string{"Bearer "}},
		{"authorization": []string{"bearer"}},
		{"X-Management-Key": []string{"  "}},
	} {
		status, _, _ = callManagement(t, pluginapi.ManagementRequest{
			Method:  http.MethodPost,
			Path:    managementCallbackRoute,
			Headers: header,
			Body:    []byte(`{"url":"http://127.0.0.1:18080/oauth/callback?code=` + code + `"}`),
		})
		if status != http.StatusForbidden {
			t.Fatalf("header %v status=%d", header, status)
		}
	}
}

func TestManagementPostBindsHuaweiStateThenPollExchangesOnce(t *testing.T) {
	stub := &pollPasteStub{}
	beginPollPaste(t, stub)
	start := startPollPasteLogin(t)
	const code = "remote-huawei-code"
	rawURL := "http://127.0.0.1:18080/oauth/callback?code=" + code + "&state=huawei-minted-state"
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	status, result, body := submitCallback(t, rawURL)
	if status != http.StatusOK || !result.Stored || !result.Bound || !result.Done || result.Pending {
		t.Fatalf("status=%d result=%+v", status, result)
	}
	if !strings.Contains(result.Message, "登录完成") || strings.Contains(result.Message, "等待插件认证中") {
		t.Fatalf("message=%q", result.Message)
	}
	if result.ContinueURL != "" {
		t.Fatalf("code submit returned a continue link: %q", result.ContinueURL)
	}
	if strings.Contains(string(body), code) || strings.Contains(string(body), "rt-paste") || strings.Contains(logs.String(), code) || strings.Contains(logs.String(), "huawei-minted-state") || strings.Contains(logs.String(), "rt-paste") {
		t.Fatalf("response or log leaked the callback\nbody=%s\nlog=%s", body, logs.String())
	}
	if stub.tokenHits != 1 || !strings.Contains(stub.tokenBody, code) {
		t.Fatalf("token hits=%d body=%s", stub.tokenHits, stub.tokenBody)
	}
	if _, _, ok := capturedOf(t, start.State); ok {
		t.Fatal("session remained after exchange")
	}

	againStatus, again, _ := submitCallback(t, rawURL)
	if againStatus != http.StatusConflict || again.Stored || again.Bound {
		t.Fatalf("second submit status=%d result=%+v", againStatus, again)
	}
	if stub.tokenHits != 1 {
		t.Fatalf("second submit exchanged the code, hits=%d", stub.tokenHits)
	}

	pollReq, _ := json.Marshal(map[string]any{"State": start.State})
	resp := pollLogin(t, pollReq)
	if resp.Status != pluginapi.AuthLoginStatusError {
		t.Fatalf("poll status=%q message=%q", resp.Status, resp.Message)
	}
	if stub.tokenHits != 1 {
		t.Fatalf("poll exchanged again, hits=%d body=%s", stub.tokenHits, stub.tokenBody)
	}

	thirdStatus, third, _ := submitCallback(t, rawURL)
	if thirdStatus != http.StatusConflict || third.Bound || third.Stored {
		t.Fatalf("submit after login status=%d result=%+v", thirdStatus, third)
	}
	if !strings.Contains(third.Message, "未绑定") {
		t.Fatalf("message=%q", third.Message)
	}
	if stub.tokenHits != 1 {
		t.Fatalf("token hits after repeat=%d", stub.tokenHits)
	}
	if _, _, ok := capturedOf(t, start.State); ok {
		t.Fatal("submit after login created or revived a session")
	}
}

func TestManagementPostAcceptsFormRawAndQuery(t *testing.T) {
	cases := []struct {
		name string
		req  pluginapi.ManagementRequest
	}{
		{
			name: "form",
			req: pluginapi.ManagementRequest{
				Body: []byte("url=" + url.QueryEscape("http://127.0.0.1:18080/oauth/callback?code=form-code&state=huawei")),
			},
		},
		{
			name: "raw",
			req: pluginapi.ManagementRequest{
				Body: []byte("浏览器停在 http://127.0.0.1:18080/oauth/callback?code=raw-code&state=huawei"),
			},
		},
		{
			name: "query",
			req: pluginapi.ManagementRequest{
				Query: url.Values{"redirect_url": []string{"http://127.0.0.1:18080/oauth/callback?code=query-code&state=huawei"}},
			},
		},
		{
			name: "json string",
			req: pluginapi.ManagementRequest{
				Body: []byte(`"http://127.0.0.1:18080/oauth/callback?code=string-code&state=huawei"`),
			},
		},
		{
			name: "bearer",
			req: pluginapi.ManagementRequest{
				Headers: http.Header{"Authorization": []string{"Bearer test-mgmt"}},
				Body:    []byte(`{"callback_url":"http://127.0.0.1:18080/oauth/callback?code=bearer-code&state=huawei"}`),
			},
		},
		{
			name: "json fields",
			req: pluginapi.ManagementRequest{
				Body: []byte(`{"code":"field-code","state":"huawei"}`),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &pollPasteStub{}
			beginPollPaste(t, stub)
			start := startPollPasteLogin(t)
			req := tc.req
			req.Method = http.MethodPost
			req.Path = managementCallbackFull
			if req.Headers == nil {
				req.Headers = managementHeaders("test-mgmt")
			}
			status, result, body := callManagement(t, req)
			if status != http.StatusOK || !result.Stored || !result.Done {
				t.Fatalf("status=%d result=%+v body=%s", status, result, body)
			}
			if stub.tokenHits != 1 || !strings.HasSuffix(stub.code, "-code") {
				t.Fatalf("token hits=%d code=%q", stub.tokenHits, stub.code)
			}
			if strings.Contains(string(body), stub.code) || strings.Contains(string(body), "rt-paste") {
				t.Fatalf("response leaked the code or refresh token: %s", body)
			}
			if _, _, ok := capturedOf(t, start.State); ok {
				t.Fatal("session remained after exchange")
			}
		})
	}
}

func TestManagementPostFirstHopStaysPending(t *testing.T) {
	stub := &pollPasteStub{}
	beginPollPaste(t, stub)
	start := startPollPasteLogin(t)
	rawURL := firstHopCallbackURL(pollPastePortalSecret)
	safe := protocol.SafePortalRedirect(protocol.ParseCallback(rawURL).Redirect)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	status, result, body := submitCallback(t, rawURL)
	if status != http.StatusOK || !result.Pending || !result.Stored {
		t.Fatalf("status=%d result=%+v", status, result)
	}
	if !strings.Contains(result.Message, "已记下 secret") || !strings.Contains(result.Message, "第一跳") || !strings.Contains(result.Message, "没有换票") {
		t.Fatalf("message=%q", result.Message)
	}
	if safe == "" || result.ContinueURL != safe {
		t.Fatalf("continue=%q safe=%q", result.ContinueURL, safe)
	}
	if strings.Contains(result.ContinueURL, "127.0.0.1") || strings.Contains(result.Message, pollPastePortalSecret) || strings.Contains(result.Message, "huaweicloud") {
		t.Fatalf("message or continue link echoed the loopback callback: %+v", result)
	}
	if strings.Contains(logs.String(), pollPastePortalSecret) || strings.Contains(logs.String(), "huaweicloud") || strings.Contains(logs.String(), result.ContinueURL) {
		t.Fatalf("log leaked the callback: %s", logs.String())
	}
	sessMu.Lock()
	storedRedirect := ""
	if sess := sessions[start.State]; sess != nil {
		storedRedirect = sess.CapturedRedirect
	}
	sessMu.Unlock()
	if storedRedirect != safe {
		t.Fatalf("stored redirect=%q", storedRedirect)
	}
	if !strings.Contains(string(body), "continue_url") {
		t.Fatal("response omitted the continue link")
	}
	if stub.tokenHits != 0 {
		t.Fatalf("token hits=%d", stub.tokenHits)
	}
	code, secret, ok := capturedOf(t, start.State)
	if !ok || code != "" || secret != pollPastePortalSecret {
		t.Fatalf("captured code=%q secret=%q", code, secret)
	}
	pollReq, _ := json.Marshal(map[string]any{"State": start.State})
	resp := pollLogin(t, pollReq)
	if resp.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("poll status=%q message=%q", resp.Status, resp.Message)
	}
	if stub.tokenHits != 0 {
		t.Fatalf("poll token hits=%d", stub.tokenHits)
	}
}

func TestManagementPostUnboundFirstHopKeepsContinueLink(t *testing.T) {
	resetForTest(t)
	rawURL := firstHopCallbackURL(pollPastePortalSecret)
	safe := protocol.SafePortalRedirect(protocol.ParseCallback(rawURL).Redirect)
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	status, result, _ := submitCallback(t, rawURL)
	if status != http.StatusConflict || result.Bound || result.Stored || result.Pending {
		t.Fatalf("status=%d result=%+v", status, result)
	}
	if safe == "" || result.ContinueURL != safe {
		t.Fatalf("continue=%q safe=%q", result.ContinueURL, safe)
	}
	if strings.Contains(result.Message, pollPastePortalSecret) || strings.Contains(result.Message, "huaweicloud") {
		t.Fatalf("message=%q", result.Message)
	}
	if strings.Contains(logs.String(), pollPastePortalSecret) || strings.Contains(logs.String(), "huaweicloud") {
		t.Fatalf("log leaked the callback: %s", logs.String())
	}
	sessMu.Lock()
	n := len(sessions)
	sessMu.Unlock()
	if n != 0 {
		t.Fatalf("sessions=%d", n)
	}
}

func TestManagementPostOmitsUnsafeContinueLink(t *testing.T) {
	for _, redirect := range []string{
		"https://evil.example/login",
		"javascript:alert(1)",
		"http://codearts.huaweicloud.com/portal/login",
	} {
		t.Run(redirect, func(t *testing.T) {
			resetForTest(t)
			start := startBareLogin(t)
			rawURL := "http://127.0.0.1:18080/oauth/callback?secret=portal-secret&redirect=" + url.QueryEscape(redirect)
			status, result, body := submitCallback(t, rawURL)
			if status != http.StatusOK || !result.Stored || !result.Pending {
				t.Fatalf("status=%d result=%+v", status, result)
			}
			if result.ContinueURL != "" || strings.Contains(string(body), "evil.example") || strings.Contains(string(body), "javascript:") {
				t.Fatalf("unsafe redirect returned: %+v %s", result, body)
			}
			sessMu.Lock()
			stored := ""
			if sess := sessions[start.State]; sess != nil {
				stored = sess.CapturedRedirect
			}
			sessMu.Unlock()
			if stored != "" {
				t.Fatalf("stored redirect %q", stored)
			}
		})
	}
}

func TestManagementPostDoesNotFetchPastedURL(t *testing.T) {
	hits := 0
	pastedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Error(w, "pasted URL must not be fetched", http.StatusInternalServerError)
	}))
	t.Cleanup(pastedSrv.Close)
	stub := &pollPasteStub{}
	beginPollPaste(t, stub)
	_ = startPollPasteLogin(t)
	pasted := pastedSrv.URL + "/oauth/callback?code=ssrf-code&state=huawei"
	status, result, _ := submitCallback(t, pasted)
	if status != http.StatusOK || !result.Stored || !result.Done {
		t.Fatalf("status=%d result=%+v", status, result)
	}
	if hits != 0 {
		t.Fatalf("pasted URL was fetched %d times", hits)
	}
	if stub.tokenHits != 1 || stub.code != "ssrf-code" {
		t.Fatalf("token hits=%d code=%q", stub.tokenHits, stub.code)
	}
}

func TestManagementPostBindingRules(t *testing.T) {
	t.Run("no session", func(t *testing.T) {
		resetForTest(t)
		status, result, _ := submitCallback(t, "http://127.0.0.1:18080/oauth/callback?code=orphan&state=huawei")
		if status != http.StatusConflict || result.Bound || result.Stored || !strings.Contains(result.Message, "未绑定") {
			t.Fatalf("status=%d result=%+v", status, result)
		}
		sessMu.Lock()
		n := len(sessions)
		sessMu.Unlock()
		if n != 0 {
			t.Fatalf("sessions=%d", n)
		}
	})
	t.Run("two sessions foreign state", func(t *testing.T) {
		stub := &pollPasteStub{}
		beginPollPaste(t, stub)
		older, newer := startTwoOpenLogins(t)
		status, result, _ := submitCallback(t, "http://127.0.0.1:18080/oauth/callback?code=foreign&state=neither&ticket_id=neither")
		if status != http.StatusConflict || result.Bound {
			t.Fatalf("status=%d result=%+v", status, result)
		}
		if stub.tokenHits != 0 {
			t.Fatalf("token hits=%d", stub.tokenHits)
		}
		assertCapturedEmpty(t, older.State)
		assertCapturedEmpty(t, newer.State)
	})
	t.Run("state selects one", func(t *testing.T) {
		stub := &pollPasteStub{}
		beginPollPaste(t, stub)
		older, newer := startTwoOpenLogins(t)
		olderVerifier := verifierOf(t, older.State)
		status, result, _ := submitCallback(t, "http://127.0.0.1:18080/oauth/callback?code=older-only&state="+url.QueryEscape(older.State))
		if status != http.StatusOK || !result.Stored || !result.Done {
			t.Fatalf("status=%d result=%+v", status, result)
		}
		if stub.tokenHits != 1 || stub.code != "older-only" || stub.verifier != olderVerifier {
			t.Fatalf("hits=%d code=%q verifier=%q", stub.tokenHits, stub.code, stub.verifier)
		}
		if _, _, ok := capturedOf(t, older.State); ok {
			t.Fatal("older session remained")
		}
		assertCapturedEmpty(t, newer.State)
	})
	t.Run("ticket selects one", func(t *testing.T) {
		stub := &pollPasteStub{}
		beginPollPaste(t, stub)
		older, newer := startTwoOpenLogins(t)
		newerVerifier := verifierOf(t, newer.State)
		ticket := metadataString(t, newer, "ticket_id")
		status, result, _ := submitCallback(t, "http://127.0.0.1:18080/oauth/callback?code=newer-ticket&state=huawei&ticket_id="+url.QueryEscape(ticket))
		if status != http.StatusOK || !result.Stored || !result.Done {
			t.Fatalf("status=%d result=%+v", status, result)
		}
		if stub.tokenHits != 1 || stub.code != "newer-ticket" || stub.verifier != newerVerifier {
			t.Fatalf("hits=%d code=%q verifier=%q", stub.tokenHits, stub.code, stub.verifier)
		}
		if _, _, ok := capturedOf(t, newer.State); ok {
			t.Fatal("newer session remained")
		}
		assertCapturedEmpty(t, older.State)
	})
	t.Run("state wins over another ticket", func(t *testing.T) {
		stub := &pollPasteStub{}
		beginPollPaste(t, stub)
		older, newer := startTwoOpenLogins(t)
		olderVerifier := verifierOf(t, older.State)
		ticket := metadataString(t, newer, "ticket_id")
		pasted := "http://127.0.0.1:18080/oauth/callback?code=state-wins&state=" + url.QueryEscape(older.State) + "&ticket_id=" + url.QueryEscape(ticket)
		status, result, _ := submitCallback(t, pasted)
		if status != http.StatusOK || !result.Stored || !result.Done {
			t.Fatalf("status=%d result=%+v", status, result)
		}
		if stub.tokenHits != 1 || stub.code != "state-wins" || stub.verifier != olderVerifier {
			t.Fatalf("hits=%d code=%q verifier=%q", stub.tokenHits, stub.code, stub.verifier)
		}
		if _, _, ok := capturedOf(t, older.State); ok {
			t.Fatal("older session remained")
		}
		assertCapturedEmpty(t, newer.State)
	})
}

func TestManagementSubmitDuringPollExchangesOnce(t *testing.T) {
	resetForTest(t)
	const code = "race-remote-code"
	arrived := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	unlock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unlock)
	var tokenHits int
	var tokenMu sync.Mutex
	var arriveOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, protocol.EpOAuthTokens) {
			body, _ := io.ReadAll(io.LimitReader(r.Body, maxCallbackPaste))
			tokenMu.Lock()
			tokenHits++
			tokenMu.Unlock()
			arriveOnce.Do(func() { close(arrived) })
			<-release
			if !strings.Contains(string(body), code) {
				http.Error(w, "unexpected code", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user_id":"u-race","refresh_token":"rt-race","credentials":{"access_key_id":"AKRACE","secret_access_key":"sk","security_token":"st","expiration":"2026-12-01T00:00:00Z"}}`))
			return
		}
		if strings.Contains(r.URL.Path, protocol.EpLoginTicket) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user_id":"","refresh_token":"","credentials":{}}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	SetEndpoints(endpointOverride{SnapManager: srv.URL, STSHost: srv.URL})
	SetHTTPClient(srv.Client())
	regReq, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("oauth_callback_port: 0\n")})
	_ = mustResult(t, pluginabi.MethodPluginRegister, regReq)
	start := startPollPasteLogin(t)
	pasted := "http://127.0.0.1:18080/oauth/callback?code=" + code + "&state=huawei-race"
	if captureCallback(code, "", start.State, "") == nil {
		t.Fatal("listener did not capture the code")
	}
	pollReq, _ := json.Marshal(map[string]any{"State": start.State})
	type pollAsync struct {
		resp pluginapi.AuthLoginPollResponse
		err  string
	}
	done := make(chan pollAsync, 1)
	go func() {
		resp, errText := pollLoginAsync(pollReq)
		done <- pollAsync{resp: resp, err: errText}
	}()
	select {
	case <-arrived:
	case res := <-done:
		t.Fatalf("poll returned before the token request: %+v", res)
	case <-time.After(5 * time.Second):
		t.Fatal("token request did not arrive")
	}
	status, result, _ := submitCallback(t, pasted)
	// The poll still holds the code inside exchangeCode, so the page keeps polling.
	if status != http.StatusOK || result.Stored || !result.Pending || result.Done || !strings.Contains(result.Message, "正在换票") {
		t.Fatalf("overlap submit status=%d result=%+v", status, result)
	}
	unlock()
	res := <-done
	if res.err != "" {
		t.Fatal(res.err)
	}
	if res.resp.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("poll status=%q message=%q", res.resp.Status, res.resp.Message)
	}
	tokenMu.Lock()
	hits := tokenHits
	tokenMu.Unlock()
	if hits != 1 {
		t.Fatalf("token hits=%d", hits)
	}
	if _, _, ok := capturedOf(t, start.State); ok {
		t.Fatal("session remained with a recaptured code")
	}
}

func TestManagementPostKeepsTheFirstUnclaimedCode(t *testing.T) {
	resetForTest(t)
	start := startBareLogin(t)
	if captureCallback("first-code", "", start.State, "") == nil {
		t.Fatal("capture failed")
	}
	status, result, _ := submitCallback(t, "http://127.0.0.1:18080/oauth/callback?code=second-code&state=huawei")
	if status != http.StatusConflict || result.Stored || !strings.Contains(result.Message, "另一条授权码") {
		t.Fatalf("status=%d result=%+v", status, result)
	}
	code, _, ok := capturedOf(t, start.State)
	if !ok || code != "first-code" {
		t.Fatalf("captured=%q ok=%v", code, ok)
	}
}

func TestManagementPostRejectsHugePaste(t *testing.T) {
	resetForTest(t)
	start := startBareLogin(t)
	huge := "http://127.0.0.1:18080/oauth/callback?code=" + strings.Repeat("a", maxCallbackPaste)
	status, result, _ := submitCallback(t, huge)
	if status != http.StatusRequestEntityTooLarge || result.Stored || result.Bound {
		t.Fatalf("status=%d result=%+v", status, result)
	}
	code, _, ok := capturedOf(t, start.State)
	if !ok || code != "" {
		t.Fatalf("captured=%q", code)
	}
}

func TestManagementPostEmptyPaste(t *testing.T) {
	resetForTest(t)
	start := startBareLogin(t)
	status, result, _ := submitCallback(t, "   ")
	if status != http.StatusBadRequest || result.Stored {
		t.Fatalf("status=%d result=%+v", status, result)
	}
	code, _, ok := capturedOf(t, start.State)
	if !ok || code != "" {
		t.Fatalf("captured=%q", code)
	}
}

func TestLoopbackCallbackStillCapturesWithoutManagementPage(t *testing.T) {
	resetForTest(t)
	start := startBareLogin(t)
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?code=loopback-code&state=huawei-loop", nil)
	rec := httptest.NewRecorder()
	handleOAuthCallbackHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	code, _, ok := capturedOf(t, start.State)
	if !ok || code != "loopback-code" {
		t.Fatalf("captured=%q ok=%v", code, ok)
	}
	if strings.Contains(rec.Body.String(), managementCallbackFull) {
		t.Fatal("loopback page pointed at the management submit route")
	}
}

func TestManagementHandleRejectsInvalidJSON(t *testing.T) {
	resetForTest(t)
	env := mustHandle(t, pluginabi.MethodManagementHandle, []byte(`{`))
	if env.OK {
		t.Fatal("invalid management request was accepted")
	}
}

func startBareLogin(t *testing.T) pluginapi.AuthLoginStartResponse {
	t.Helper()
	regReq, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("oauth_callback_port: 0\n")})
	_ = mustResult(t, pluginabi.MethodPluginRegister, regReq)
	return startPollPasteLogin(t)
}

func startTwoLogins(t *testing.T) (older, newer pluginapi.AuthLoginStartResponse) {
	t.Helper()
	regReq, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("oauth_callback_port: 0\n")})
	_ = mustResult(t, pluginabi.MethodPluginRegister, regReq)
	return startTwoOpenLogins(t)
}

func startTwoOpenLogins(t *testing.T) (older, newer pluginapi.AuthLoginStartResponse) {
	t.Helper()
	older = startPollPasteLogin(t)
	restore := keepSession(t, older.State)
	newer = startPollPasteLogin(t)
	restore()
	if older.State == newer.State {
		t.Fatal("login states collided")
	}
	return older, newer
}

func metadataString(t *testing.T, start pluginapi.AuthLoginStartResponse, key string) string {
	t.Helper()
	v, _ := start.Metadata[key].(string)
	if v == "" {
		t.Fatalf("missing metadata %s in %+v", key, start.Metadata)
	}
	return v
}

func assertCapturedEmpty(t *testing.T, id string) {
	t.Helper()
	code, secret, ok := capturedOf(t, id)
	if !ok || code != "" || secret != "" {
		t.Fatalf("session %s captured code=%q secret=%q ok=%v", id, code, secret, ok)
	}
}

func pollLoginAsync(request []byte) (pluginapi.AuthLoginPollResponse, string) {
	raw, err := Handle(pluginabi.MethodAuthLoginPoll, request)
	if err != nil {
		return pluginapi.AuthLoginPollResponse{}, err.Error()
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return pluginapi.AuthLoginPollResponse{}, err.Error()
	}
	if !env.OK {
		msg := "auth.login.poll not ok"
		if env.Error != nil {
			msg = env.Error.Code + ": " + env.Error.Message
		}
		return pluginapi.AuthLoginPollResponse{}, msg
	}
	var resp pluginapi.AuthLoginPollResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		return pluginapi.AuthLoginPollResponse{}, err.Error()
	}
	return resp, ""
}

func managementHeaders(key string) http.Header {
	return http.Header{"X-Management-Key": []string{key}}
}

func submitCallback(t *testing.T, raw string) (int, managementResult, []byte) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"url": raw})
	if err != nil {
		t.Fatal(err)
	}
	return callManagement(t, pluginapi.ManagementRequest{
		Method:  http.MethodPost,
		Path:    managementCallbackFull,
		Headers: managementHeaders("test-mgmt"),
		Body:    body,
	})
}

func callManagement(t *testing.T, req pluginapi.ManagementRequest) (int, managementResult, []byte) {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
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
