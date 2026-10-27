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
	captureCallback(code, secret, state, ticketID)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if code == "" {
		safe := protocol.SafePortalRedirect(redirect)
		if secret != "" || safe != "" {
			var b strings.Builder
			b.WriteString(`<!doctype html><html lang="zh-cn"><head><meta charset="utf-8"><title>CodeArts 回调</title></head><body>`)
			b.WriteString(`<h3>已接收华为第一跳回调（secret），登录尚未完成。</h3>`)
			b.WriteString(`<p>本页不会自动跳转。请在新标签打开华为授权，并留着本页。</p>`)
			if safe != "" {
				b.WriteString(`<p><a href="` + html.EscapeString(safe) + `" target="_blank" rel="noopener noreferrer">继续华为授权</a></p>`)
			}
			b.WriteString(`<p>完成后把<strong>含 code=</strong> 的完整 URL 粘贴到 CPA 管理界面的 OAuth 登录。</p></body></html>`)
			_, _ = w.Write([]byte(b.String()))
			return
		}
		_, _ = w.Write([]byte("<!doctype html><html><body><h3>还没有授权码，这不是最终失败。</h3><p>把浏览器地址栏完整 URL 粘贴到 CPA 管理界面的 OAuth 登录。第一跳只有 secret，第二跳才有 code=。</p></body></html>"))
		return
	}
	_, _ = w.Write([]byte("<!doctype html><html><body><h3>已接收授权码，可关闭此页面。</h3><p>回到 CLIProxyAPI 等待 auth.login.poll 完成。</p></body></html>"))
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
