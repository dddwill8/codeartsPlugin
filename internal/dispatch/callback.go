package dispatch

import (
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/dddwill8/codeartsPlugin/internal/protocol"
)

var (
	listenMu     sync.Mutex
	listener     net.Listener
	listenKey    string
	listenServer *http.Server
)

func ensureCallbackListener(cfg Config) {
	if cfg.CallbackPort <= 0 {
		return
	}
	addr := cfg.CallbackHost + ":" + itoa(cfg.CallbackPort)
	listenMu.Lock()
	defer listenMu.Unlock()
	if listenKey == addr && listener != nil {
		return
	}
	stopCallbackListenerLocked()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		hostLog("warn", "codearts oauth callback listen failed: "+err.Error())
		return
	}
	mux := http.NewServeMux()
	path := cfg.CallbackPath
	if path == "" {
		path = "/oauth/callback"
	}
	mux.HandleFunc(path, handleOAuthCallbackHTTP)
	srv := &http.Server{Handler: mux}
	listener = ln
	listenServer = srv
	listenKey = addr
	go func() { _ = srv.Serve(ln) }()
}

func stopCallbackListener() {
	listenMu.Lock()
	defer listenMu.Unlock()
	stopCallbackListenerLocked()
}

func stopCallbackListenerLocked() {
	if listenServer != nil {
		_ = listenServer.Close()
	}
	if listener != nil {
		_ = listener.Close()
	}
	listener = nil
	listenServer = nil
	listenKey = ""
}

func handleOAuthCallbackHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	secret := q.Get("secret")
	redirect := q.Get("redirect")
	state := q.Get("state")
	ticketID := q.Get("ticket_id")
	if code == "" {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		vals, _ := url.ParseQuery(string(body))
		if code == "" {
			code = vals.Get("code")
		}
		if secret == "" {
			secret = vals.Get("secret")
		}
		if redirect == "" {
			redirect = vals.Get("redirect")
		}
		if state == "" {
			state = vals.Get("state")
		}
		if ticketID == "" {
			ticketID = vals.Get("ticket_id")
		}
	}
	bound := captureCallback(code, secret, state, ticketID)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(oauthCallbackPage(bound, code, secret, redirect)))
}

// managementCallbackURL is the second hop CPA accepts. state is the login
// session id registered with CPA, not a state Huawei returned.
func managementCallbackURL(port int, code, state string) string {
	if port <= 0 {
		port = 18080
	}
	q := url.Values{}
	q.Set("code", code)
	q.Set("state", state)
	return "http://127.0.0.1:" + itoa(port) + "/oauth/callback?" + q.Encode()
}

// oauthCallbackPage tells the user what to do with this hop.
// A bound callback that already has a code shows one URL whose state is the
// login session id. A first hop (secret or portal redirect, no code) records
// that locally and does not offer a URL CPA would accept. An unmatched
// callback does not claim the code was received and does not show a URL.
func oauthCallbackPage(bound *loginSession, code, secret, redirect string) string {
	safe := protocol.SafePortalRedirect(redirect)
	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="zh-cn"><head><meta charset="utf-8"><title>CodeArts 回调</title></head><body>`)
	if code == "" && (secret != "" || safe != "") {
		if bound != nil {
			b.WriteString(`<h3>已接收华为第一跳回调（secret），登录尚未完成。</h3>`)
			b.WriteString(`<p>secret 已记在本地。请继续华为授权，并留着本页。这一跳没有授权码，不要提交到管理界面。</p>`)
		} else {
			b.WriteString(`<h3>未绑定到进行中的登录。</h3>`)
			b.WriteString(`<p>这次回调没有对上进行中的会话，secret 没有记在本地。不要提交到管理界面。</p>`)
		}
		if safe != "" {
			b.WriteString(`<p><a href="` + html.EscapeString(safe) + `" target="_blank" rel="noopener noreferrer">继续华为授权</a></p>`)
		}
		b.WriteString(`</body></html>`)
		return b.String()
	}
	if code != "" && bound != nil {
		paste := managementCallbackURL(bound.Port, code, bound.ID)
		b.WriteString(`<h3>已接收授权码。</h3>`)
		b.WriteString(`<p>回到「码道登录」页面即可，状态查询会完成登录。下面这一条只在需要手工提交时使用。不要粘贴浏览器地址栏里的原文。</p>`)
		b.WriteString(`<p><code>` + html.EscapeString(paste) + `</code></p>`)
		b.WriteString(`</body></html>`)
		return b.String()
	}
	if code != "" || secret != "" {
		b.WriteString(`<h3>未绑定到进行中的登录。</h3>`)
		b.WriteString(`<p>请回到 CPA 管理界面，取消当前 codearts 登录后重新点一次，再完成华为授权。新的回调页会给出可粘贴的 URL。不要提交地址栏原文。</p></body></html>`)
		return b.String()
	}
	b.WriteString(`<h3>还没有授权码，这不是最终失败。</h3>`)
	b.WriteString(`<p>第一跳只有 secret，第二跳才有授权码。不要把地址栏原文提交到管理界面。</p></body></html>`)
	return b.String()
}

func applyPastedCallback(raw string) protocol.CallbackParts {
	parts := protocol.ParseCallback(raw)
	bound := captureCallback(parts.Code, parts.Secret, parts.State, parts.TicketID)
	if bound != nil {
		if safe := protocol.SafePortalRedirect(parts.Redirect); safe != "" {
			sessMu.Lock()
			bound.CapturedRedirect = safe
			sessMu.Unlock()
		}
	}
	return parts
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
