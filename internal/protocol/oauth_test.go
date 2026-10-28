package protocol

import (
	"net/url"
	"testing"
)

func TestBuildAuthorizeURLContainsRequiredQuery(t *testing.T) {
	cfg := DefaultLoginConfig()
	got := BuildAuthorizeURL(cfg, "ticket-abc", "challenge-xyz", 18080)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "codearts.huaweicloud.com" || u.Path != "/portal/authorize" {
		t.Fatalf("url = %s", got)
	}
	q := u.Query()
	if q.Get("client_id") != "codearts-agent" {
		t.Fatalf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("code_challenge") != "challenge-xyz" {
		t.Fatalf("code_challenge = %q", q.Get("code_challenge"))
	}
	if q.Get("ticket_id") != "ticket-abc" {
		t.Fatalf("ticket_id = %q", q.Get("ticket_id"))
	}
	if q.Get("code_challenge_method") != "SHA-256" {
		t.Fatalf("code_challenge_method = %q", q.Get("code_challenge_method"))
	}
}

func TestExtractCallbackCode(t *testing.T) {
	code := ExtractCallbackCode("http://127.0.0.1:18080/oauth/callback?code=abc%2Fdef&secret=s")
	if code != "abc/def" {
		t.Fatalf("code = %q", code)
	}
	if ExtractCallbackCode("plain-code") != "plain-code" {
		t.Fatalf("raw code")
	}
}

func TestParseCallbackFirstHopSecretRedirect(t *testing.T) {
	const pasted = "http://127.0.0.1/oauth/callback?secret=4246780b5c346fe0d0539f80545238652effd265af12fde05a06bd2e137a4f7e&redirect=https%3A%2F%2Fcodearts.huaweicloud.com%2Fportal%2Flogin%3Ftheme%3Dlight%26locale%3Dzh-cn%26authorizationAvailable%3Dfalse%26secret%3D4246780b5c346fe0d0539f80545238652effd265af12fde05a06bd2e137a4f7e"
	const wantSecret = "4246780b5c346fe0d0539f80545238652effd265af12fde05a06bd2e137a4f7e"
	const wantRedirect = "https://codearts.huaweicloud.com/portal/login?theme=light&locale=zh-cn&authorizationAvailable=false&secret=4246780b5c346fe0d0539f80545238652effd265af12fde05a06bd2e137a4f7e"

	parts := ParseCallback(pasted)
	if parts.Code != "" {
		t.Fatalf("first hop must not invent a code: %+v", parts)
	}
	if parts.Secret != wantSecret {
		t.Fatalf("secret = %q", parts.Secret)
	}
	if parts.Redirect != wantRedirect {
		t.Fatalf("redirect = %q", parts.Redirect)
	}
	if SafePortalRedirect(parts.Redirect) != wantRedirect {
		t.Fatalf("unsafe redirect: %q", SafePortalRedirect(parts.Redirect))
	}
	if parts.State != "" || parts.TicketID != "" {
		t.Fatalf("first hop invented binding keys: %+v", parts)
	}

	labeled := ParseCallback("回调地址为：" + pasted)
	if labeled.Secret != wantSecret || labeled.Redirect != wantRedirect || labeled.Code != "" {
		t.Fatalf("labeled paste = %+v", labeled)
	}
}

func TestCallbackParseStateAndTicketID(t *testing.T) {
	const raw = "http://127.0.0.1:18080/oauth/callback?code=abc&state=sess-1&ticket_id=ticket-9"
	parts := ParseCallback(raw)
	if parts.Code != "abc" || parts.State != "sess-1" || parts.TicketID != "ticket-9" {
		t.Fatalf("url parts = %+v", parts)
	}
	loose := ParseCallback("code=abc&state=sess-1&ticket_id=ticket-9")
	if loose.Code != "abc" || loose.State != "sess-1" || loose.TicketID != "ticket-9" {
		t.Fatalf("loose parts = %+v", loose)
	}
}
