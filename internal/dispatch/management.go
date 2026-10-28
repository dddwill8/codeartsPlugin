package dispatch

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"

	"github.com/dddwill8/codeartsPlugin/internal/protocol"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	// managementLoginRoute starts one plugin-page login. The state it returns
	// stays in the plugin and is not registered in CPA's OAuth session table.
	managementLoginRoute = "/codearts/oauth-start"
	managementLoginFull  = "/v0/management" + managementLoginRoute

	// managementCallbackRoute is the authenticated POST that accepts one pasted
	// loopback URL and exchanges it. It is not a browser resource: resource
	// requests are public.
	managementCallbackRoute = "/codearts/oauth-callback"
	managementCallbackFull  = "/v0/management" + managementCallbackRoute

	// managementStatusRoute polls the plugin-page session. The loopback listener
	// only captures; this route exchanges when a code is already stored.
	managementStatusRoute = "/codearts/oauth-status"
	managementStatusFull  = "/v0/management" + managementStatusRoute

	// resourceCallbackRoute is the CPAMP plugin-menu page. GET only.
	// CPA prefixes it with ResourceBasePath, which is
	// /v0/resource/plugins/<id> and <id> comes from the .so filename.
	resourceCallbackRoute = "/callback"
	resourcePluginsPrefix = "/v0/resource/plugins/"
	resourceCallbackFull  = resourcePluginsPrefix + protocol.PluginID + resourceCallbackRoute

	// maxCallbackPaste matches the loopback listener body cap. Larger pastes are
	// rejected before they can be stored on a session.
	maxCallbackPaste = 64 << 10

	managementMenuName = "码道登录"
)

var errCallbackTooLarge = errors.New("callback paste too large")

// pluginIDPattern matches CPA pluginIDFromPath. Release files such as
// codearts-linux-amd64.so have no "-v" version suffix, so the id is the
// whole basename, not protocol.PluginID.
var pluginIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

var (
	resourceBaseMu         sync.Mutex
	registeredResourceBase string
)

type managementRouteJSON struct {
	Method      string `json:"Method"`
	Path        string `json:"Path"`
	Menu        string `json:"Menu,omitempty"`
	Description string `json:"Description,omitempty"`
}

type resourceRouteJSON struct {
	Path        string `json:"Path"`
	Menu        string `json:"Menu"`
	Description string `json:"Description"`
}

type managementRegistrationJSON struct {
	Routes    []managementRouteJSON `json:"routes"`
	Resources []resourceRouteJSON   `json:"resources"`
}

// managementResult is the JSON body of the authenticated submit route.
// Messages are fixed sentences. They do not include the pasted URL, code,
// secret, ticket, or management key. ContinueURL is set only for a first hop,
// and only to the safe portal redirect.
type managementResult struct {
	OK          bool   `json:"ok"`
	Bound       bool   `json:"bound"`
	Stored      bool   `json:"stored"`
	Pending     bool   `json:"pending"`
	Message     string `json:"message"`
	ContinueURL string `json:"continue_url,omitempty"`
	AuthURL     string `json:"auth_url,omitempty"`
	State       string `json:"state,omitempty"`
	Label       string `json:"label,omitempty"`
	Done        bool   `json:"done,omitempty"`
}

func handleManagementRegister(request []byte) ([]byte, error) {
	if len(request) > 0 {
		var req pluginapi.ManagementRegistrationRequest
		if json.Unmarshal(request, &req) == nil {
			rememberResourceBase(req.ResourceBasePath)
		}
	}
	return okEnvelope(managementRegistration())
}

func rememberResourceBase(raw string) {
	base := cleanResourceBase(raw)
	if base == "" {
		return
	}
	resourceBaseMu.Lock()
	registeredResourceBase = base
	resourceBaseMu.Unlock()
}

func currentResourceBase() string {
	resourceBaseMu.Lock()
	defer resourceBaseMu.Unlock()
	return registeredResourceBase
}

func clearResourceBase() {
	resourceBaseMu.Lock()
	registeredResourceBase = ""
	resourceBaseMu.Unlock()
}

func cleanResourceBase(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "..") || strings.ContainsAny(raw, " \t\r\n?#\\") {
		return ""
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	cleaned := path.Clean(raw)
	if !strings.HasPrefix(cleaned, "/") || cleaned == "/" {
		return ""
	}
	return cleaned
}

func managementRegistration() managementRegistrationJSON {
	return managementRegistrationJSON{
		Routes: []managementRouteJSON{
			{
				Method:      http.MethodPost,
				Path:        managementLoginRoute,
				Description: "开始码道登录。需要 CPA 管理认证。",
			},
			{
				Method:      http.MethodPost,
				Path:        managementCallbackRoute,
				Description: "接收地址栏里的华为回调 URL，并完成换票。需要 CPA 管理认证。",
			},
			{
				Method:      http.MethodPost,
				Path:        managementStatusRoute,
				Description: "查询本次登录状态。需要 CPA 管理认证。",
			},
		},
		Resources: []resourceRouteJSON{{
			Path:        resourceCallbackRoute,
			Menu:        managementMenuName,
			Description: "在这一页登录码道。远程时把地址栏里的完整回调 URL 交到这里。",
		}},
	}
}

func handleManagement(request []byte) ([]byte, error) {
	if len(request) > 1<<20 {
		return managementJSON(http.StatusRequestEntityTooLarge, managementResult{Message: "回调内容过长。"})
	}
	var req pluginapi.ManagementRequest
	if len(request) == 0 || json.Unmarshal(request, &req) != nil {
		return errorEnvelope("invalid_management_request", "management request is not JSON", http.StatusBadRequest), nil
	}
	// host_callback_id is a sibling of the management request, same as auth.login.poll.
	// An empty id keeps hostHTTPDo on its direct dial.
	callbackID := jsonString(request, "host_callback_id", "HostCallbackID")
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	switch {
	case method == http.MethodGet && isCallbackPagePath(req.Path):
		return managementBytes(http.StatusOK, "text/html; charset=utf-8", pageCSP(), managementPage())
	case method == http.MethodPost && samePath(req.Path, managementLoginFull, managementLoginRoute):
		return startManagementLogin(req)
	case method == http.MethodPost && samePath(req.Path, managementCallbackFull, managementCallbackRoute):
		return submitManagementCallback(req, callbackID)
	case method == http.MethodPost && samePath(req.Path, managementStatusFull, managementStatusRoute):
		return queryManagementLogin(req, callbackID)
	case isResourceCallbackPath(req.Path):
		// The public resource must not accept a code, even as POST with a body.
		return managementJSON(http.StatusMethodNotAllowed, managementResult{
			Message: "这个页面只展示说明，不接收授权码。",
		})
	default:
		return managementJSON(http.StatusNotFound, managementResult{Message: "未知的管理路径。"})
	}
}

func isCallbackPagePath(raw string) bool {
	if isResourceCallbackPath(raw) {
		return true
	}
	return samePath(raw, managementCallbackFull, managementCallbackRoute)
}

// isResourceCallbackPath reports whether raw is the paste page.
// The relative route, the ResourceBasePath from management.register, and any
// /v0/resource/plugins/<id>/callback all count. The id is the .so basename.
func isResourceCallbackPath(raw string) bool {
	requestPath := normalizeRequestPath(raw)
	if requestPath == "" {
		return false
	}
	if requestPath == resourceCallbackRoute {
		return true
	}
	if base := currentResourceBase(); base != "" && requestPath == base+resourceCallbackRoute {
		return true
	}
	if !strings.HasPrefix(requestPath, resourcePluginsPrefix) {
		return false
	}
	id, route, ok := strings.Cut(strings.TrimPrefix(requestPath, resourcePluginsPrefix), "/")
	return ok && route == "callback" && pluginIDPattern.MatchString(id)
}

func normalizeRequestPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	return strings.TrimRight(raw, "/")
}

func samePath(path, full, rel string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	path = strings.TrimRight(path, "/")
	return path == full || path == rel
}

func startManagementLogin(req pluginapi.ManagementRequest) ([]byte, error) {
	if !managementAuthorized(req.Headers) {
		log.Printf("codearts management login http=403")
		return managementJSON(http.StatusForbidden, managementResult{Message: "需要管理认证。"})
	}
	sess, err := beginLoginSession()
	if err != nil {
		log.Printf("codearts management login http=500")
		return managementJSON(http.StatusInternalServerError, managementResult{Message: "登录没有开始。请再点一次。"})
	}
	log.Printf("codearts management login http=200")
	return managementJSON(http.StatusOK, managementResult{
		OK:      true,
		AuthURL: sess.AuthURL,
		State:   sess.ID,
		Pending: true,
		Message: "已开始登录。请在打开的页面完成华为授权。",
	})
}

func queryManagementLogin(req pluginapi.ManagementRequest, callbackID string) ([]byte, error) {
	if !managementAuthorized(req.Headers) {
		log.Printf("codearts management status http=403")
		return managementJSON(http.StatusForbidden, managementResult{Message: "需要管理认证。"})
	}
	state := managementLoginState(req.Body, req.Query)
	result := loginStatus(state, callbackID)
	log.Printf("codearts management status http=%d pending=%t done=%t", result.Status, result.Pending, result.Done)
	return managementJSON(result.Status, result.managementResult)
}

func loginStatus(state, callbackID string) bindOutcome {
	if state == "" {
		return bindOutcome{
			Status: http.StatusOK,
			managementResult: managementResult{
				Message: "没有进行中的登录。请重新点登录。",
			},
		}
	}
	sess := getSession(state)
	if sess == nil {
		if done, ok := doneTerminalOutcome(state); ok {
			return done
		}
		return bindOutcome{
			Status: http.StatusOK,
			managementResult: managementResult{
				Message: "没有进行中的登录。请重新点登录。",
			},
		}
	}
	out := redeemCaptured(sess, callbackID)
	if out.Busy {
		return exchangingOutcome()
	}
	if out.SaveFailed {
		return fileNotWrittenOutcome()
	}
	if out.Hard != nil {
		return bindOutcome{
			Status: http.StatusBadGateway,
			managementResult: managementResult{
				Bound:   true,
				Message: "换票没有完成。请重新点登录后再授权。",
			},
		}
	}
	if out.Exchanged {
		return bindOutcome{
			Status: http.StatusOK,
			managementResult: managementResult{
				OK:      true,
				Done:    true,
				Bound:   true,
				Label:   out.Label,
				Message: "登录完成。认证文件已写入。",
			},
		}
	}
	if out.Rejected || out.PriorFailure {
		return bindOutcome{
			Status: http.StatusOK,
			managementResult: managementResult{
				Bound:   true,
				Message: "授权码被拒绝，没有写入认证文件。请重新点登录后再授权。",
			},
		}
	}
	if out.Secret != "" {
		return bindOutcome{
			Status: http.StatusOK,
			managementResult: managementResult{
				OK:      true,
				Bound:   true,
				Pending: true,
				Message: "已记下 secret，登录仍在等待。这是第一跳，没有换票。请继续华为授权。",
			},
		}
	}
	return bindOutcome{
		Status: http.StatusOK,
		managementResult: managementResult{
			OK:      true,
			Bound:   true,
			Pending: true,
			Message: "等待华为授权。本机回调会自动完成；远程时把地址栏里的完整 URL 贴回这一页。",
		},
	}
}

func submitManagementCallback(req pluginapi.ManagementRequest, callbackID string) ([]byte, error) {
	if !managementAuthorized(req.Headers) {
		log.Printf("codearts management callback http=403")
		return managementJSON(http.StatusForbidden, managementResult{Message: "需要管理认证。"})
	}
	raw, err := pastedCallbackText(req.Body, req.Query)
	if err != nil {
		log.Printf("codearts management callback http=413")
		return managementJSON(http.StatusRequestEntityTooLarge, managementResult{Message: "回调内容过长。"})
	}
	result := bindPastedCallback(protocol.ParseCallback(raw), callbackID, pastedLoginState(req.Body))
	log.Printf("codearts management callback http=%d bound=%t stored=%t pending=%t done=%t", result.Status, result.Bound, result.Stored, result.Pending, result.Done)
	return managementJSON(result.Status, result.managementResult)
}

type bindOutcome struct {
	managementResult
	Status int
}

// bindPastedCallback stores the paste on one in-flight session. A stored
// authorization code is exchanged here. A first hop only records the secret.
// pageState, when set, binds only that session and does not open a new one.
// An unexpired success for pageState or the callback state returns the same
// done result as loginStatus and does not capture or exchange. A retired id
// with no success terminal stays unbound, so a replaced login cannot accept
// the old code.
func bindPastedCallback(parts protocol.CallbackParts, callbackID, pageState string) bindOutcome {
	pageState = strings.TrimSpace(pageState)
	if done, ok := doneTerminalOutcome(pageState); ok {
		return done
	}
	if done, ok := doneTerminalOutcome(parts.State); ok {
		return done
	}
	if isRetiredSession(parts.State) {
		return finishBind(parts, unboundLoginResult())
	}
	if pageState != "" {
		if getSession(pageState) == nil || isRetiredSession(pageState) {
			return finishBind(parts, unboundLoginResult())
		}
		if parts.State == "" || getSession(parts.State) == nil {
			parts.State = pageState
		}
	}
	return finishBind(parts, bindPastedCallbackResult(parts, callbackID))
}

func unboundLoginResult() bindOutcome {
	return bindOutcome{
		Status: http.StatusConflict,
		managementResult: managementResult{
			Message: "未绑定。没有进行中的登录。请重新点登录。没有写入任何会话。",
		},
	}
}

func doneTerminalOutcome(id string) (bindOutcome, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return bindOutcome{}, false
	}
	term, ok := terminalOf(id)
	if !ok || !term.OK {
		return bindOutcome{}, false
	}
	return bindOutcome{
		Status: http.StatusOK,
		managementResult: managementResult{
			OK:      true,
			Done:    true,
			Label:   term.Label,
			Message: "登录完成。",
		},
	}, true
}

func fileNotWrittenOutcome() bindOutcome {
	return bindOutcome{
		Status: http.StatusBadGateway,
		managementResult: managementResult{
			Bound:   true,
			Message: "认证文件没有写入。请重新点登录后再授权。",
		},
	}
}

func exchangingOutcome() bindOutcome {
	return bindOutcome{
		Status: http.StatusOK,
		managementResult: managementResult{
			OK:      true,
			Bound:   true,
			Pending: true,
			Message: "正在换票。",
		},
	}
}

func bindPastedCallbackResult(parts protocol.CallbackParts, callbackID string) bindOutcome {
	if parts.Code == "" && parts.Secret == "" {
		return bindOutcome{
			Status: http.StatusBadRequest,
			managementResult: managementResult{
				Message: "没有看到授权码或 secret。请粘贴地址栏里的完整 URL。",
			},
		}
	}
	sess := captureCallback(parts.Code, parts.Secret, parts.State, parts.TicketID)
	if sess == nil {
		return bindOutcome{
			Status: http.StatusConflict,
			managementResult: managementResult{
				Message: "未绑定。没有进行中的登录，或有多个进行中的登录且 state、ticket_id 都未命中。没有写入任何会话。",
			},
		}
	}
	safeRedirect := protocol.SafePortalRedirect(parts.Redirect)
	sessMu.Lock()
	capturedCode := sess.CapturedCode
	capturedSecret := sess.CapturedSecret
	_, claimed := sess.claimedCodes[parts.Code]
	if parts.Code == "" && capturedSecret == parts.Secret && safeRedirect != "" {
		sess.CapturedRedirect = safeRedirect
	}
	sessMu.Unlock()
	if sessionSaveBlocked(sess) {
		return fileNotWrittenOutcome()
	}

	if parts.Code != "" {
		if capturedCode == parts.Code {
			return exchangeBoundCode(sess, callbackID)
		}
		if claimed {
			return bindOutcome{
				Status: http.StatusOK,
				managementResult: managementResult{
					OK:      true,
					Bound:   true,
					Message: "这条授权码已经交给过进行中的登录，不会再次换票。",
				},
			}
		}
		return bindOutcome{
			Status: http.StatusConflict,
			managementResult: managementResult{
				OK:      true,
				Bound:   true,
				Message: "进行中的登录还留着另一条授权码，这一条没有写入。等当前轮询结束，或取消后重新登录再提交。",
			},
		}
	}
	if capturedSecret == parts.Secret {
		return bindOutcome{
			Status: http.StatusOK,
			managementResult: managementResult{
				OK:      true,
				Bound:   true,
				Stored:  true,
				Pending: true,
				Message: "已记下 secret，登录仍在等待。这是第一跳，没有换票。请继续华为授权；拿到带 code 的地址后再提交。",
			},
		}
	}
	return bindOutcome{
		Status: http.StatusConflict,
		managementResult: managementResult{
			OK:      true,
			Bound:   true,
			Message: "进行中的登录已经有 secret，这一条没有写入。",
		},
	}
}

func exchangeBoundCode(sess *loginSession, callbackID string) bindOutcome {
	out := redeemCaptured(sess, callbackID)
	if out.Busy {
		return exchangingOutcome()
	}
	if out.SaveFailed {
		return fileNotWrittenOutcome()
	}
	if out.Hard != nil {
		return bindOutcome{
			Status: http.StatusBadGateway,
			managementResult: managementResult{
				Bound:   true,
				Message: "换票没有完成。请重新点登录后再授权。",
			},
		}
	}
	if out.Exchanged {
		return bindOutcome{
			Status: http.StatusOK,
			managementResult: managementResult{
				OK:      true,
				Bound:   true,
				Stored:  true,
				Done:    true,
				Label:   out.Label,
				Message: "登录完成。认证文件已写入。",
			},
		}
	}
	if out.Rejected || out.PriorFailure {
		return bindOutcome{
			Status: http.StatusOK,
			managementResult: managementResult{
				Bound:   true,
				Stored:  true,
				Message: "授权码被拒绝，没有写入认证文件。请重新点登录后再授权。",
			},
		}
	}
	return bindOutcome{
		Status: http.StatusOK,
		managementResult: managementResult{
			OK:      true,
			Bound:   true,
			Message: "这条授权码已经交给过进行中的登录，不会再次换票。",
		},
	}
}

func managementLoginState(body []byte, query url.Values) string {
	if state := jsonBodyField(body, "login_state"); state != "" {
		return state
	}
	if state := jsonBodyField(body, "state"); state != "" {
		return state
	}
	return firstQuery(query, "login_state", "state")
}

// pastedLoginState is the plugin page's session id. It is not the state Huawei
// put on the callback URL. A callback "state" field must not select the session
// by this path; captureCallback still reads that state from the URL.
func pastedLoginState(body []byte) string {
	return jsonBodyField(body, "login_state")
}

func jsonBodyField(body []byte, key string) string {
	trim := bytesTrimLeft(body)
	if len(trim) == 0 || trim[0] != '{' {
		return ""
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(trim, &m) != nil {
		return ""
	}
	return jsonStringField(m, key)
}

func bytesTrimLeft(body []byte) []byte {
	i := 0
	for i < len(body) && (body[i] == ' ' || body[i] == '\n' || body[i] == '\r' || body[i] == '\t') {
		i++
	}
	return body[i:]
}

// finishBind adds the portal continue link for a first hop. The fixed message
// stays free of the URL. A second hop that already has a code does not.
func finishBind(parts protocol.CallbackParts, out bindOutcome) bindOutcome {
	if parts.Code != "" {
		return out
	}
	if safe := protocol.SafePortalRedirect(parts.Redirect); safe != "" {
		out.ContinueURL = safe
	}
	return out
}

func pastedCallbackText(body []byte, query url.Values) (string, error) {
	if len(body) > maxCallbackPaste {
		return "", errCallbackTooLarge
	}
	raw := strings.TrimSpace(string(body))
	if raw == "" {
		raw = firstQuery(query, "url", "redirect_url", "callback_url", "callback")
		if len(raw) > maxCallbackPaste {
			return "", errCallbackTooLarge
		}
		return raw, nil
	}
	if strings.HasPrefix(raw, `"`) {
		var s string
		if json.Unmarshal(body, &s) == nil {
			s = strings.TrimSpace(s)
			if len(s) > maxCallbackPaste {
				return "", errCallbackTooLarge
			}
			return s, nil
		}
	}
	if strings.HasPrefix(raw, "{") {
		var m map[string]json.RawMessage
		if json.Unmarshal(body, &m) == nil {
			s := jsonStringField(m, "url", "redirect_url", "callback_url", "callback")
			if s == "" {
				q := url.Values{}
				for _, key := range []string{"code", "secret", "redirect", "state", "ticket_id"} {
					if field := jsonStringField(m, key); field != "" {
						q.Set(key, field)
					}
				}
				if len(q) > 0 {
					s = "http://127.0.0.1/oauth/callback?" + q.Encode()
				}
			}
			if len(s) > maxCallbackPaste {
				return "", errCallbackTooLarge
			}
			return s, nil
		}
	}
	if looksLikeForm(raw) {
		vals, err := url.ParseQuery(raw)
		if err == nil {
			s := firstQuery(vals, "url", "redirect_url", "callback_url", "callback")
			if len(s) > maxCallbackPaste {
				return "", errCallbackTooLarge
			}
			return s, nil
		}
	}
	return raw, nil
}

func jsonStringField(m map[string]json.RawMessage, keys ...string) string {
	for _, key := range keys {
		raw, ok := m[key]
		if !ok {
			for k, v := range m {
				if strings.EqualFold(k, key) {
					raw = v
					ok = true
					break
				}
			}
		}
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			if s = strings.TrimSpace(s); s != "" {
				return s
			}
		}
	}
	return ""
}

func looksLikeForm(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	for _, key := range []string{"url=", "redirect_url=", "callback_url=", "callback="} {
		if strings.HasPrefix(lower, key) {
			return true
		}
	}
	return false
}

func firstQuery(q url.Values, keys ...string) string {
	if len(q) == 0 {
		return ""
	}
	for _, key := range keys {
		if v := strings.TrimSpace(q.Get(key)); v != "" {
			return v
		}
		for k, vs := range q {
			if !strings.EqualFold(k, key) {
				continue
			}
			for _, v := range vs {
				if s := strings.TrimSpace(v); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

// managementAuthorized mirrors CPA management middleware. The host already
// rejects a public POST before it reaches the plugin. This check covers a
// direct management.handle call that did not carry the credential.
func managementAuthorized(h http.Header) bool {
	if headerValue(h, "X-Management-Key") != "" {
		return true
	}
	auth := headerValue(h, "Authorization")
	if auth == "" {
		return false
	}
	parts := strings.SplitN(auth, " ", 2)
	if strings.EqualFold(parts[0], "Bearer") {
		return len(parts) == 2 && strings.TrimSpace(parts[1]) != ""
	}
	return true
}

func headerValue(h http.Header, name string) string {
	if len(h) == 0 {
		return ""
	}
	if v := strings.TrimSpace(h.Get(name)); v != "" {
		return v
	}
	for k, vs := range h {
		if !strings.EqualFold(k, name) {
			continue
		}
		for _, v := range vs {
			if s := strings.TrimSpace(v); s != "" {
				return s
			}
		}
	}
	return ""
}

func callbackPortLabel() string {
	port := currentConfig().CallbackPort
	if port <= 0 {
		port = 18080
	}
	return itoa(port)
}

func pageCSP() string {
	return "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'"
}

func managementPage() []byte {
	cfg, _ := json.Marshal(map[string]string{
		"start":  managementLoginFull,
		"post":   managementCallbackFull,
		"status": managementStatusFull,
		"port":   callbackPortLabel(),
	})
	page := `<!doctype html><html lang="zh-cn"><head><meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<title>码道登录</title>
<style>
body{font:16px/1.5 sans-serif;margin:2rem auto;max-width:40rem;padding:0 1rem;color:#1a1a1a}
label{display:block;margin:1rem 0 .3rem}
textarea,input{width:100%;box-sizing:border-box;font:inherit}
textarea{min-height:6rem}
button{margin-top:1rem;font:inherit;padding:.4rem 1rem}
#result{white-space:pre-wrap}
code,#authlink{word-break:break-all}
</style></head><body>
<h3>码道登录</h3>
<p>点「登录」，在打开的页面完成华为授权。不需要打开 CPAMP 的 OAuth 卡片。</p>
<p>华为会把浏览器带到本机的 <code>http://127.0.0.1:__PORT__/oauth/callback?...</code>。如果 Chrome 显示无法连接，地址栏里的完整 URL 就是回调。把它贴到下面。</p>
<p>不要把这条 URL 贴进 CPA 的 OAuth 回调框。那条入口认不出华为带回的 state。</p>
<p>本机浏览器能打开回调页时，不用粘贴。这一页会查询状态并完成登录。</p>
<p><label for="key">管理密钥（与登录 CPAMP 相同）</label>
<input id="key" name="key" type="password" autocomplete="current-password"></p>
<p><button id="login" type="button">登录</button></p>
<p id="authlink"></p>
<form id="form">
<label for="url">地址栏里的完整 URL</label>
<textarea id="url" name="url" spellcheck="false" autocomplete="off"></textarea>
<button id="submit" type="submit">提交</button>
</form>
<p id="result" role="status"></p>
<p id="continue"></p>
<noscript><p>需要启用 JavaScript，才能带上管理密钥提交。没有脚本时这个页面不会把 URL 发出去。</p></noscript>
<script>
const cfg = __CFG__;
const form = document.getElementById('form');
const urlBox = document.getElementById('url');
const keyBox = document.getElementById('key');
const result = document.getElementById('result');
const button = document.getElementById('submit');
const loginButton = document.getElementById('login');
const storageKey = 'codearts.managementKey';
let loginState = '';
let pollTimer = 0;
let pollGen = 0;
let pollAbort = null;

function textBytes(s){return new TextEncoder().encode(s)}
function fromB64(b64){
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function xorString(bytes, key){
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[i] ^ key[i % key.length];
  return new TextDecoder().decode(out);
}
function managementKeyFrom(obj){
  if (!obj || typeof obj !== 'object') return '';
  if (typeof obj.managementKey === 'string') return obj.managementKey;
  if (obj.state && typeof obj.state.managementKey === 'string') return obj.state.managementKey;
  return '';
}
function readPanelKey(){
  let raw = '';
  try { raw = localStorage.getItem('cli-proxy-auth') || ''; } catch (e) { return ''; }
  if (!raw) return '';
  let text = raw;
  const prefix = 'enc::v1::';
  if (raw.startsWith(prefix)) {
    try {
      const key = textBytes('cli-proxy-api-webui::secure-storage|' + location.host + '|' + navigator.userAgent);
      text = xorString(fromB64(raw.slice(prefix.length)), key);
    } catch (e) { return ''; }
  }
  try {
    let obj = JSON.parse(text);
    if (typeof obj === 'string') obj = JSON.parse(obj);
    return managementKeyFrom(obj);
  } catch (e) { return ''; }
}
function savedKey(){
  try {
    const saved = sessionStorage.getItem(storageKey) || '';
    if (saved) return saved;
  } catch (e) {}
  return readPanelKey();
}
function rememberKey(key, ok){
  try {
    if (!ok) sessionStorage.removeItem(storageKey);
    else if (key) sessionStorage.setItem(storageKey, key);
  } catch (e) {}
}
function apiURL(path){
  const marker = '/v0/resource/';
  const loc = location.pathname || '';
  const at = loc.indexOf(marker);
  if (at >= 0) return loc.slice(0, at) + path;
  return path;
}
function postURL(){return apiURL(cfg.post)}
function stopPoll(){
  if (pollTimer) { clearTimeout(pollTimer); pollTimer = 0; }
  if (pollAbort) { pollAbort.abort(); pollAbort = null; }
}
function safeAuthURL(url){
  if (typeof url !== 'string' || url === '') return '';
  let parsed;
  try { parsed = new URL(url); } catch (e) { return ''; }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) return '';
  const host = parsed.hostname.toLowerCase();
  if (host !== 'codearts.huaweicloud.com' && !host.endsWith('.huaweicloud.com')) return '';
  return url;
}
function showAuthLink(url){
  const box = document.getElementById('authlink');
  box.replaceChildren();
  const safe = safeAuthURL(url);
  if (!safe) return;
  const link = document.createElement('a');
  link.href = safe;
  link.target = '_blank';
  link.rel = 'noopener noreferrer';
  link.textContent = safe;
  box.appendChild(link);
}
function showStatus(data, status, text){
  result.textContent = resultMessage(status, text);
  if (data && data.label) result.textContent += '（' + data.label + '）';
  showContinue(data && data.continue_url);
  if (data && data.done) stopPoll();
}
async function pollOnce(){
  if (!loginState) return;
  const gen = pollGen;
  const state = loginState;
  const key = keyBox.value.replace(/[\r\n]/g, '').trim();
  if (!key) return;
  const abort = new AbortController();
  if (gen !== pollGen || state !== loginState) return;
  if (pollAbort) pollAbort.abort();
  pollAbort = abort;
  try {
    const resp = await fetch(apiURL(cfg.status), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Management-Key': key
      },
      body: JSON.stringify({state: state}),
      credentials: 'same-origin',
      signal: abort.signal
    });
    if (gen !== pollGen || state !== loginState) return;
    const text = await resp.text();
    if (gen !== pollGen || state !== loginState) return;
    let data = null;
    try { data = JSON.parse(text); } catch (e) {}
    if (data && (data.done || data.pending !== true)) {
      if (gen !== pollGen || state !== loginState) return;
      showStatus(data, resp.status, text);
      return;
    }
    if (data && data.pending && !urlBox.value.trim() && gen === pollGen && state === loginState) result.textContent = resultMessage(resp.status, text);
    if (gen !== pollGen || state !== loginState) return;
    pollTimer = setTimeout(pollOnce, 2000);
  } catch (e) {
    if (gen !== pollGen || state !== loginState) return;
    if (e && e.name === 'AbortError') return;
    pollTimer = setTimeout(pollOnce, 2000);
  }
}
function resultMessage(status, text){
  try {
    const data = JSON.parse(text);
    if (typeof data.message === 'string' && data.message) return data.message;
    if (typeof data.error === 'string' && data.error) return data.error;
  } catch (e) {}
  if (status === 403) return '需要管理认证。填写和 CPAMP 相同的管理密钥。';
  return '提交失败（' + status + '）';
}
function keepURL(data){
  return !data || data.stored !== true || data.pending === true;
}
function portalContinueURL(url){
  if (typeof url !== 'string' || url === '') return '';
  let parsed;
  try { parsed = new URL(url); } catch (e) { return ''; }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) return '';
  const host = parsed.hostname.toLowerCase();
  if (host !== 'codearts.huaweicloud.com' && !host.endsWith('.huaweicloud.com')) return '';
  return url;
}
function showContinue(url){
  const box = document.getElementById('continue');
  box.replaceChildren();
  const safe = portalContinueURL(url);
  if (!safe) return;
  const link = document.createElement('a');
  link.href = safe;
  link.target = '_blank';
  link.rel = 'noopener noreferrer';
  link.textContent = '继续华为授权';
  box.appendChild(link);
}
keyBox.value = savedKey();
loginButton.addEventListener('click', async function () {
  const key = keyBox.value.replace(/[\r\n]/g, '').trim();
  result.textContent = '';
  showContinue('');
  if (!key) {
    result.textContent = '先填写管理密钥。它和登录 CPAMP 时相同。';
    return;
  }
  const popup = window.open('', '_blank');
  loginButton.disabled = true;
  stopPoll();
  pollGen++;
  loginState = '';
  try {
    const resp = await fetch(apiURL(cfg.start), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Management-Key': key
      },
      body: '{}',
      credentials: 'same-origin'
    });
    const text = await resp.text();
    let data = null;
    try { data = JSON.parse(text); } catch (e) {}
    const auth = data && safeAuthURL(data.auth_url);
    loginState = data && typeof data.state === 'string' ? data.state : '';
    showAuthLink(auth || '');
    if (popup) {
      if (auth) popup.location = auth;
      else popup.close();
    }
    result.textContent = resultMessage(resp.status, text);
    rememberKey(key, resp.status !== 403);
    if (loginState && data && data.pending) pollTimer = setTimeout(pollOnce, 1000);
  } catch (e) {
    if (popup) popup.close();
    result.textContent = '登录没有送到 CPA。确认这个页面是从 CPA 打开的。';
  } finally {
    loginButton.disabled = false;
  }
});
form.addEventListener('submit', async function (ev) {
  ev.preventDefault();
  const pasted = urlBox.value.trim();
  const key = keyBox.value.replace(/[\r\n]/g, '').trim();
  result.textContent = '';
  if (!pasted) {
    result.textContent = '先粘贴地址栏里的完整 URL。';
    showContinue('');
    return;
  }
  if (!key) {
    result.textContent = '先填写管理密钥。它和登录 CPAMP 时相同。';
    return;
  }
  button.disabled = true;
  try {
    const resp = await fetch(postURL(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Management-Key': key
      },
      body: JSON.stringify({url: pasted, login_state: loginState}),
      credentials: 'same-origin'
    });
    const text = await resp.text();
    let data = null;
    try { data = JSON.parse(text); } catch (e) {}
    showStatus(data, resp.status, text);
    if (!keepURL(data)) urlBox.value = '';
    rememberKey(key, resp.status !== 403);
  } catch (e) {
    result.textContent = '提交没有送到 CPA。确认这个页面是从 CPA 打开的。';
  } finally {
    button.disabled = false;
  }
});
</script>
</body></html>`
	page = strings.ReplaceAll(page, "__PORT__", callbackPortLabel())
	page = strings.ReplaceAll(page, "__CFG__", string(cfg))
	return []byte(page)
}

func managementJSON(status int, result managementResult) ([]byte, error) {
	body, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return managementBytes(status, "application/json; charset=utf-8", "", body)
}

func managementBytes(status int, contentType, csp string, body []byte) ([]byte, error) {
	headers := http.Header{
		"Content-Type":           []string{contentType},
		"Cache-Control":          []string{"no-store"},
		"Referrer-Policy":        []string{"no-referrer"},
		"X-Content-Type-Options": []string{"nosniff"},
		"X-Robots-Tag":           []string{"noindex"},
	}
	if csp != "" {
		headers.Set("Content-Security-Policy", csp)
	}
	return okEnvelope(pluginapi.ManagementResponse{
		StatusCode: status,
		Headers:    headers,
		Body:       body,
	})
}
