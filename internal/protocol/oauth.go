package protocol

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// LoginConfig is the Huawei OAuth/PKCE configuration.
type LoginConfig struct {
	ClientID      string
	PortalHost    string
	SnapManager   string
	STSHost       string
	RedirectPath  string
	PluginName    string
	PluginVersion string
}

// DefaultLoginConfig matches the official CodeArts Agent plugin.
func DefaultLoginConfig() LoginConfig {
	return LoginConfig{
		ClientID:      ClientID,
		PortalHost:    PortalHost,
		SnapManager:   SnapManagerHost,
		STSHost:       STSHost,
		RedirectPath:  "/oauth/callback",
		PluginName:    OAuthPluginName,
		PluginVersion: OAuthPluginVersion,
	}
}

// BuildAuthorizeURL constructs https://codearts.huaweicloud.com/portal/authorize?...
func BuildAuthorizeURL(cfg LoginConfig, ticketID, codeChallenge string, port int) string {
	if cfg.ClientID == "" {
		cfg.ClientID = ClientID
	}
	if cfg.PortalHost == "" {
		cfg.PortalHost = PortalHost
	}
	if cfg.PluginName == "" {
		cfg.PluginName = OAuthPluginName
	}
	if cfg.PluginVersion == "" {
		cfg.PluginVersion = OAuthPluginVersion
	}
	q := url.Values{}
	q.Set("theme", "2")
	q.Set("locale", "zh-cn")
	q.Set("uri_scheme", cfg.ClientID)
	q.Set("client_id", cfg.ClientID)
	q.Set("port", fmt.Sprint(port))
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "SHA-256")
	q.Set("ticket_id", ticketID)
	q.Set("plugin-name", cfg.PluginName)
	q.Set("plugin-version", cfg.PluginVersion)
	return strings.TrimRight(cfg.PortalHost, "/") + "/authorize?" + q.Encode()
}

// RedirectURI is the loopback URI Huawei binds to the authorization code.
func RedirectURI(cfg LoginConfig, port int) string {
	path := cfg.RedirectPath
	if path == "" {
		path = "/oauth/callback"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if port <= 0 {
		port = 18080
	}
	return fmt.Sprintf("http://127.0.0.1:%d%s", port, path)
}

// TokenFormAuthorizationCode is the STS form for grant_type=authorization_code.
func TokenFormAuthorizationCode(cfg LoginConfig, code, codeVerifier string, port int) url.Values {
	form := url.Values{}
	form.Set("client_id", cfg.ClientID)
	form.Set("code", code)
	form.Set("code_verifier", codeVerifier)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", RedirectURI(cfg, port))
	return form
}

// TokenFormRefresh is the STS form for grant_type=refresh_token.
func TokenFormRefresh(cfg LoginConfig, refreshToken, codeVerifier string) url.Values {
	form := url.Values{}
	form.Set("client_id", cfg.ClientID)
	form.Set("code_verifier", codeVerifier)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	return form
}

// TokenEndpoint is the STS oauth2/tokens URL.
func TokenEndpoint(cfg LoginConfig) string {
	host := cfg.STSHost
	if host == "" {
		host = STSHost
	}
	return strings.TrimRight(host, "/") + EpOAuthTokens
}

// TicketURL is the snap-manager ticket poll URL.
func TicketURL(cfg LoginConfig, ticketID, secret string) string {
	host := cfg.SnapManager
	if host == "" {
		host = SnapManagerHost
	}
	return strings.TrimRight(host, "/") + EpLoginTicket + "?ticket_id=" + url.QueryEscape(ticketID) + "&secret=" + url.QueryEscape(secret)
}

// NewTokenRequest builds a POST to STS with form body and DPoP proof.
func NewTokenRequest(cfg LoginConfig, form url.Values, dpop DPoPPrivateJWK) (*http.Request, error) {
	endpoint := TokenEndpoint(cfg)
	proof, err := SignDPoPProof(dpop, endpoint)
	if err != nil {
		return nil, fmt.Errorf("dpop proof: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", proof)
	return req, nil
}

// NewTicketRequest builds GET snap-manager /v1/login/ticket.
func NewTicketRequest(cfg LoginConfig, ticketID, secret string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, TicketURL(cfg, ticketID, secret), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("plugin-name", cfg.PluginName)
	req.Header.Set("plugin-version", cfg.PluginVersion)
	return req, nil
}

// DoJSON performs req with client and reads at most maxBody bytes.
func DoJSON(client *http.Client, req *http.Request, maxBody int64) (status int, body []byte, err error) {
	if client == nil {
		client = http.DefaultClient
	}
	if maxBody <= 0 {
		maxBody = 4 << 20
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return resp.StatusCode, raw, nil
}

// CallbackParts is the Huawei loopback callback: first hop is secret+redirect,
// second hop carries the authorization code.
type CallbackParts struct {
	Code     string
	Secret   string
	Redirect string
}

// ParseCallback extracts code / secret / redirect from a pasted callback URL,
// a labeled Chinese prompt, or a raw authorization code.
func ParseCallback(raw string) CallbackParts {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return CallbackParts{}
	}
	if extracted := extractHTTPURL(raw); extracted != "" {
		parts := partsFromURL(extracted)
		if parts.Code == "" {
			parts.Code = queryValue(raw, "code")
		}
		if parts.Secret == "" {
			parts.Secret = queryValue(raw, "secret")
		}
		if parts.Redirect == "" {
			parts.Redirect = queryValue(raw, "redirect")
		}
		if parts.Secret == "" && parts.Redirect != "" {
			if ru, err := url.Parse(parts.Redirect); err == nil {
				parts.Secret = ru.Query().Get("secret")
			}
		}
		return parts
	}
	if strings.Contains(raw, "code=") || strings.Contains(raw, "secret=") || strings.Contains(raw, "redirect=") {
		parts := CallbackParts{
			Code:     queryValue(raw, "code"),
			Secret:   queryValue(raw, "secret"),
			Redirect: queryValue(raw, "redirect"),
		}
		if parts.Secret == "" && parts.Redirect != "" {
			if ru, err := url.Parse(parts.Redirect); err == nil {
				parts.Secret = ru.Query().Get("secret")
			}
		}
		return parts
	}
	if !strings.Contains(raw, "://") && !strings.Contains(raw, "?") {
		return CallbackParts{Code: raw}
	}
	return CallbackParts{}
}

// ExtractCallbackCode pulls an OAuth code from a pasted callback URL or raw code.
func ExtractCallbackCode(raw string) string {
	return ParseCallback(raw).Code
}

// ExtractCallbackSecret pulls portal-issued secret from a callback URL.
func ExtractCallbackSecret(raw string) string {
	return ParseCallback(raw).Secret
}

// ExtractCallbackRedirect pulls the Huawei continue-login URL from a first-hop callback.
func ExtractCallbackRedirect(raw string) string {
	return ParseCallback(raw).Redirect
}

// SafePortalRedirect returns raw if it is an https Huawei portal/login URL.
func SafePortalRedirect(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || !strings.EqualFold(u.Scheme, "https") {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "codearts.huaweicloud.com" || strings.HasSuffix(host, ".huaweicloud.com") {
		return raw
	}
	return ""
}

func extractHTTPURL(raw string) string {
	lower := strings.ToLower(raw)
	idx := -1
	for _, scheme := range []string{"https://", "http://"} {
		i := strings.Index(lower, scheme)
		if i >= 0 && (idx < 0 || i < idx) {
			idx = i
		}
	}
	if idx < 0 {
		return ""
	}
	rest := raw[idx:]
	if j := strings.IndexAny(rest, " \t\r\n<>\"'"); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimRight(rest, "。．，,")
}

func partsFromURL(rawURL string) CallbackParts {
	u, err := url.Parse(rawURL)
	if err != nil {
		return CallbackParts{
			Code:     queryValue(rawURL, "code"),
			Secret:   queryValue(rawURL, "secret"),
			Redirect: queryValue(rawURL, "redirect"),
		}
	}
	q := u.Query()
	return CallbackParts{
		Code:     q.Get("code"),
		Secret:   q.Get("secret"),
		Redirect: q.Get("redirect"),
	}
}

func queryValue(raw, key string) string {
	src := raw
	if i := strings.Index(raw, "?"); i >= 0 {
		src = raw[i+1:]
	}
	vals, err := url.ParseQuery(src)
	if err == nil {
		if v := strings.TrimSpace(vals.Get(key)); v != "" {
			return v
		}
	}
	prefix := key + "="
	lower := strings.ToLower(src)
	idx := strings.Index(lower, strings.ToLower(prefix))
	if idx < 0 {
		return ""
	}
	rest := src[idx+len(prefix):]
	if j := strings.IndexAny(rest, "&?#"); j >= 0 {
		rest = rest[:j]
	}
	out, err := url.QueryUnescape(rest)
	if err != nil {
		return rest
	}
	return out
}
