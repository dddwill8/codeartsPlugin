package dispatch

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/dddwill8/codeartsPlugin/internal/protocol"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	// managementCallbackRoute is the authenticated POST that accepts one pasted
	// loopback URL. It is not a browser resource: resource requests are public.
	managementCallbackRoute = "/codearts/oauth-callback"
	managementCallbackFull  = "/v0/management" + managementCallbackRoute

	// resourceCallbackRoute is the CPAMP plugin-menu page. GET only.
	resourceCallbackRoute = "/callback"
	resourceCallbackFull  = "/v0/resource/plugins/" + protocol.PluginID + resourceCallbackRoute

	// maxCallbackPaste matches the loopback listener body cap. Larger pastes are
	// rejected before they can be stored on a session.
	maxCallbackPaste = 64 << 10

	managementMenuName = "提交华为回调"
)

var errCallbackTooLarge = errors.New("callback paste too large")

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
// secret, ticket, or management key.
type managementResult struct {
	OK      bool   `json:"ok"`
	Bound   bool   `json:"bound"`
	Stored  bool   `json:"stored"`
	Pending bool   `json:"pending"`
	Message string `json:"message"`
}

func managementRegistration() managementRegistrationJSON {
	return managementRegistrationJSON{
		Routes: []managementRouteJSON{{
			Method:      http.MethodPost,
			Path:        managementCallbackRoute,
			Description: "接收地址栏里的华为回调 URL。需要 CPA 管理认证。",
		}},
		Resources: []resourceRouteJSON{{
			Path:        resourceCallbackRoute,
			Menu:        managementMenuName,
			Description: "Chrome 无法连接本机回调时，把地址栏里的完整 URL 交到这里。",
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
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	switch {
	case method == http.MethodGet && isCallbackPagePath(req.Path):
		return managementBytes(http.StatusOK, "text/html; charset=utf-8", pageCSP(), managementPage())
	case method == http.MethodPost && samePath(req.Path, managementCallbackFull, managementCallbackRoute):
		return submitManagementCallback(req)
	case samePath(req.Path, resourceCallbackFull, resourceCallbackRoute):
		// The public resource must not accept a code, even as POST with a body.
		return managementJSON(http.StatusMethodNotAllowed, managementResult{
			Message: "这个页面只展示说明，不接收授权码。",
		})
	default:
		return managementJSON(http.StatusNotFound, managementResult{Message: "未知的管理路径。"})
	}
}

func isCallbackPagePath(path string) bool {
	return samePath(path, resourceCallbackFull, resourceCallbackRoute) ||
		samePath(path, managementCallbackFull, managementCallbackRoute)
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

func submitManagementCallback(req pluginapi.ManagementRequest) ([]byte, error) {
	if !managementAuthorized(req.Headers) {
		log.Printf("codearts management callback http=403")
		return managementJSON(http.StatusForbidden, managementResult{Message: "需要管理认证。"})
	}
	raw, err := pastedCallbackText(req.Body, req.Query)
	if err != nil {
		log.Printf("codearts management callback http=413")
		return managementJSON(http.StatusRequestEntityTooLarge, managementResult{Message: "回调内容过长。"})
	}
	result := bindPastedCallback(protocol.ParseCallback(raw))
	log.Printf("codearts management callback http=%d bound=%t stored=%t pending=%t", result.Status, result.Bound, result.Stored, result.Pending)
	return managementJSON(result.Status, result.managementResult)
}

type bindOutcome struct {
	managementResult
	Status int
}

// bindPastedCallback stores the paste on one in-flight session and does not
// exchange it. The next auth.login.poll claims the code once.
func bindPastedCallback(parts protocol.CallbackParts) bindOutcome {
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
	sessMu.Lock()
	capturedCode := sess.CapturedCode
	capturedSecret := sess.CapturedSecret
	_, claimed := sess.claimedCodes[parts.Code]
	sessMu.Unlock()

	if parts.Code != "" {
		if capturedCode == parts.Code {
			return bindOutcome{
				Status: http.StatusOK,
				managementResult: managementResult{
					OK:      true,
					Bound:   true,
					Stored:  true,
					Message: "已交给进行中的登录。回到 CPAMP，保持「等待插件认证中」，等这一轮轮询结束。不要把这条 URL 贴进 CPA 的 OAuth 回调框。",
				},
			}
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
		"post": managementCallbackFull,
		"port": callbackPortLabel(),
	})
	page := `<!doctype html><html lang="zh-cn"><head><meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<title>提交华为回调</title>
<style>
body{font:16px/1.5 sans-serif;margin:2rem auto;max-width:40rem;padding:0 1rem;color:#1a1a1a}
label{display:block;margin:1rem 0 .3rem}
textarea,input{width:100%;box-sizing:border-box;font:inherit}
textarea{min-height:6rem}
button{margin-top:1rem;font:inherit;padding:.4rem 1rem}
#result{white-space:pre-wrap}
code{word-break:break-all}
</style></head><body>
<h3>提交华为回调</h3>
<p>在 CPAMP 里点过「开始 codearts 登录」后，卡片要一直停在「等待插件认证中」。不要取消。</p>
<p>华为会把浏览器带到本机的 <code>http://127.0.0.1:__PORT__/oauth/callback?...</code>。如果 Chrome 显示无法连接，地址栏里的完整 URL 就是回调。把它贴到下面。</p>
<p>不要把这条 URL 贴进 CPA 的 OAuth 回调框。那条入口认不出华为带回的 state。</p>
<p>本机浏览器能打开回调页时，不用这个页面。监听器会自己收下授权码。</p>
<form id="form">
<label for="url">地址栏里的完整 URL</label>
<textarea id="url" name="url" spellcheck="false" autocomplete="off"></textarea>
<label for="key">管理密钥（与登录 CPAMP 相同）</label>
<input id="key" name="key" type="password" autocomplete="current-password">
<button id="submit" type="submit">提交</button>
</form>
<p id="result" role="status"></p>
<noscript><p>需要启用 JavaScript，才能带上管理密钥提交。没有脚本时这个页面不会把 URL 发出去。</p></noscript>
<script>
const cfg = __CFG__;
const form = document.getElementById('form');
const urlBox = document.getElementById('url');
const keyBox = document.getElementById('key');
const result = document.getElementById('result');
const button = document.getElementById('submit');
const storageKey = 'codearts.managementKey';

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
function postURL(){
  const marker = '/v0/resource/';
  const path = location.pathname || '';
  const at = path.indexOf(marker);
  if (at >= 0) return path.slice(0, at) + cfg.post;
  return cfg.post;
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
keyBox.value = savedKey();
form.addEventListener('submit', async function (ev) {
  ev.preventDefault();
  const pasted = urlBox.value.trim();
  const key = keyBox.value.replace(/[\r\n]/g, '').trim();
  result.textContent = '';
  if (!pasted) {
    result.textContent = '先粘贴地址栏里的完整 URL。';
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
      body: JSON.stringify({url: pasted}),
      credentials: 'same-origin'
    });
    const text = await resp.text();
    result.textContent = resultMessage(resp.status, text);
    const retry = resp.status === 403 || resp.status === 400 || resp.status === 413;
    if (!retry) urlBox.value = '';
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
