package dispatch

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dddwill8/codeartsPlugin/internal/protocol"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type loginSession struct {
	ID               string
	TicketID         string
	Secret           string
	Verifier         string
	DPoP             protocol.DPoPPrivateJWK
	Port             int
	AuthURL          string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	CapturedCode     string
	CapturedSecret   string
	CapturedRedirect string
	// claimedCodes are authorization codes this session already handed to
	// exchangeCode. The same value must not be stored in CapturedCode again.
	claimedCodes map[string]struct{}
}

var (
	sessMu   sync.Mutex
	sessions = map[string]*loginSession{}
)

func handleAuthParse(request []byte) ([]byte, error) {
	var req pluginapi.AuthParseRequest
	if len(request) > 0 {
		_ = json.Unmarshal(request, &req)
	}
	fileName := req.FileName
	if fileName == "" {
		fileName = jsonString(request, "FileName", "file_name")
	}
	raw := req.RawJSON
	if len(raw) == 0 {
		raw = jsonBytes(request, "RawJSON", "raw_json")
	}
	if !protocol.LooksLikeCodeArts(raw, fileName) {
		return okEnvelope(pluginapi.AuthParseResponse{Handled: false})
	}
	c, err := protocol.ParseCredential(raw)
	if err != nil {
		return okEnvelope(pluginapi.AuthParseResponse{Handled: false})
	}
	return okEnvelope(pluginapi.AuthParseResponse{
		Handled: true,
		Auth:    authDataFromCredential(c, fileName),
	})
}

func handleLoginStart(_ []byte) ([]byte, error) {
	cfg := currentConfig()
	lc := loginConfig()
	ticketID, err := protocol.RandomHex(16)
	if err != nil {
		return errorEnvelope("login_error", err.Error(), http.StatusInternalServerError), nil
	}
	secret, err := protocol.RandomHex(16)
	if err != nil {
		return errorEnvelope("login_error", err.Error(), http.StatusInternalServerError), nil
	}
	verifier, challenge, err := protocol.PKCE()
	if err != nil {
		return errorEnvelope("login_error", err.Error(), http.StatusInternalServerError), nil
	}
	dpop, err := protocol.NewDPoPPrivateJWK()
	if err != nil {
		return errorEnvelope("login_error", err.Error(), http.StatusInternalServerError), nil
	}
	port := cfg.CallbackPort
	if port <= 0 {
		port = 18080
	}
	state, err := protocol.RandomHex(16)
	if err != nil {
		return errorEnvelope("login_error", err.Error(), http.StatusInternalServerError), nil
	}
	authURL := protocol.BuildAuthorizeURL(lc, ticketID, challenge, port)
	now := time.Now().UTC()
	sess := &loginSession{
		ID:        state,
		TicketID:  ticketID,
		Secret:    secret,
		Verifier:  verifier,
		DPoP:      dpop,
		Port:      port,
		AuthURL:   authURL,
		CreatedAt: now,
		ExpiresAt: now.Add(15 * time.Minute),
	}
	putSession(sess)
	ensureCallbackListener(cfg)
	return okEnvelope(pluginapi.AuthLoginStartResponse{
		Provider:  protocol.Provider,
		URL:       authURL,
		State:     state,
		ExpiresAt: sess.ExpiresAt,
		Metadata: map[string]any{
			"ticket_id":     ticketID,
			"callback_path": protocol.RedirectURI(lc, port),
		},
	})
}

func handleLoginPoll(request []byte) ([]byte, error) {
	state := jsonString(request, "State", "state")
	if state == "" {
		var req pluginapi.AuthLoginPollRequest
		_ = json.Unmarshal(request, &req)
		state = req.State
	}
	sess := getSession(state)
	if sess == nil {
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: "unknown or expired login state",
		})
	}
	if time.Now().After(sess.ExpiresAt) {
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: "login flow expired",
		})
	}
	// Paste and .oauth-codearts-<state>.oauth are the inputs the loopback
	// listener would have stored. Binding stays inside captureCallback.
	ingestPollCallback(request, state)
	lc := loginConfig()
	callbackID := jsonString(request, "host_callback_id", "HostCallbackID")
	capturedCode, capturedSecret := claimCaptured(sess)

	if capturedCode != "" {
		tok, err := exchangeCode(callbackID, lc, sess, capturedCode)
		if err != nil {
			// The code was claimed before exchange. Do not clear CapturedCode
			// again: captureCallback may have stored a newer code during the
			// HTTP call, and that code must remain.
			return okEnvelope(pluginapi.AuthLoginPollResponse{
				Status:  pluginapi.AuthLoginStatusPending,
				Message: "authorization code rejected: " + err.Error() + "; paste a new callback URL or reset login",
			})
		}
		return completeLogin(sess, tok, callbackID)
	}

	// Ticket GET is not DPoP-bound. Completing on ticket STS would persist
	// sess.DPoP beside credentials whose refresh_token (if any) was issued
	// without that key, and it races the authorization_code exchange.
	tok, err := pollTicket(callbackID, lc, sess, capturedSecret)
	msg := "waiting for Huawei authorization code"
	if capturedSecret != "" {
		msg = "received portal secret; continue Huawei login, then paste the callback page URL that has this session's state and code="
	}
	if err != nil {
		msg = "pending: " + err.Error()
	} else if tok.HasSTS() && tok.RefreshToken == "" {
		msg = "ticket returned STS without DPoP-bound refresh_token; waiting for authorization code"
	} else if tok.HasSTS() {
		msg = "ticket credentials are not DPoP-bound; waiting for authorization code"
	}
	return okEnvelope(pluginapi.AuthLoginPollResponse{
		Status:  pluginapi.AuthLoginStatusPending,
		Message: msg,
	})
}

func handleRefresh(request []byte) ([]byte, error) {
	var req pluginapi.AuthRefreshRequest
	_ = json.Unmarshal(request, &req)
	raw := req.StorageJSON
	if len(raw) == 0 {
		raw = jsonBytes(request, "StorageJSON", "storage_json")
	}
	prev, err := protocol.ParseCredential(raw)
	if err != nil {
		return errorEnvelope("refresh_error", err.Error(), http.StatusBadRequest), nil
	}
	if prev.RefreshToken == "" || prev.ClientID == "" || prev.DPoPPrivateKey["d"] == "" {
		return errorEnvelope("refresh_error", "credential missing client_id, refresh_token, or DPoP private key", http.StatusUnauthorized), nil
	}
	lc := loginConfig()
	lc.ClientID = prev.ClientID
	form := protocol.TokenFormRefresh(lc, prev.RefreshToken, prev.CodeVerifier)
	httpReq, err := protocol.NewTokenRequest(lc, form, prev.DPoPPrivateKey)
	if err != nil {
		return errorEnvelope("refresh_error", err.Error(), http.StatusInternalServerError), nil
	}
	callbackID := jsonString(request, "host_callback_id", "HostCallbackID")
	resp, err := hostHTTPDo(callbackID, httpReq)
	if err != nil {
		return errorEnvelope("refresh_error", err.Error(), http.StatusBadGateway), nil
	}
	defer resp.Body.Close()
	body, _ := protocol.ReadAllLimited(resp.Body, 4<<20)
	if resp.StatusCode >= 400 {
		status := resp.StatusCode
		if status == http.StatusBadRequest {
			status = http.StatusUnauthorized
		}
		return errorEnvelope("refresh_error", fmt.Sprintf("sts refresh http=%d body=%s", resp.StatusCode, truncate(string(body), 240)), status), nil
	}
	tok, err := protocol.ParseTokenResponse(body)
	if err != nil {
		return errorEnvelope("refresh_error", err.Error(), http.StatusBadGateway), nil
	}
	if !tok.HasSTS() {
		return errorEnvelope("refresh_error", "sts refresh missing credentials", http.StatusBadGateway), nil
	}
	next := protocol.ApplyRefresh(prev, tok)
	fileName := jsonString(request, "FileName", "file_name")
	derived := protocol.FileNameFor(next)
	// An omitted name or the shared unknown placeholder follows the credential.
	// Any other caller-supplied name stays, even when it differs from derived.
	if (fileName == "" || fileName == "codearts-unknown.json") && derived != fileName {
		fileName = derived
	}
	rawNext, err := protocol.MarshalCredential(next)
	if err != nil {
		return errorEnvelope("refresh_error", err.Error(), http.StatusInternalServerError), nil
	}
	_ = hostAuthSave(fileName, rawNext)
	auth := authDataFromCredential(next, fileName)
	auth.ID = jsonString(request, "AuthID", "auth_id")
	if auth.ID == "" {
		auth.ID = protocol.FileNameFor(next)
	}
	return okEnvelope(pluginapi.AuthRefreshResponse{
		Auth:             auth,
		NextRefreshAfter: auth.NextRefreshAfter,
	})
}

func completeLogin(sess *loginSession, tok protocol.TokenResponse, callbackID string) ([]byte, error) {
	if !tok.HasSTS() || strings.TrimSpace(tok.RefreshToken) == "" {
		return errorEnvelope("login_error", "refusing to persist STS without DPoP-bound refresh_token", http.StatusUnauthorized), nil
	}
	lc := loginConfig()
	cred := protocol.NewCredentialFromToken(tok, sess.Verifier, lc.ClientID, sess.DPoP)
	if strings.TrimSpace(cred.UserID) == "" {
		fillCredentialIdentity(callbackID, lc, &cred)
	}
	raw, err := protocol.MarshalCredential(cred)
	if err != nil {
		return errorEnvelope("login_error", err.Error(), http.StatusInternalServerError), nil
	}
	fileName := protocol.FileNameFor(cred)
	_ = hostAuthSave(fileName, raw)
	delSession(sess.ID)
	return okEnvelope(pluginapi.AuthLoginPollResponse{
		Status:  pluginapi.AuthLoginStatusSuccess,
		Message: "CodeArts login complete",
		Auth:    authDataFromCredential(cred, fileName),
	})
}

// fillCredentialIdentity GETs snap-manager current user, then STS caller
// identity, only while user_id is empty. Either call failing or returning
// nothing still leaves the access key as the file name.
func fillCredentialIdentity(callbackID string, lc protocol.LoginConfig, cred *protocol.Credential) {
	if cred == nil || strings.TrimSpace(cred.UserID) != "" {
		return
	}
	if body, ok := signedIdentityGET(callbackID, snapManagerBase(lc)+protocol.EpCurrentUser, *cred); ok {
		applyCurrentUser(cred, body)
	}
	if strings.TrimSpace(cred.UserID) != "" {
		return
	}
	if body, ok := signedIdentityGET(callbackID, stsBase(lc)+protocol.EpCallerIdentity, *cred); ok {
		applyCallerIdentity(cred, body)
	}
}

func snapManagerBase(lc protocol.LoginConfig) string {
	host := strings.TrimSpace(lc.SnapManager)
	if host == "" {
		host = protocol.SnapManagerHost
	}
	return strings.TrimRight(host, "/")
}

func stsBase(lc protocol.LoginConfig) string {
	host := strings.TrimSpace(lc.STSHost)
	if host == "" {
		host = protocol.STSHost
	}
	return strings.TrimRight(host, "/")
}

func signedIdentityGET(callbackID, rawURL string, cred protocol.Credential) ([]byte, bool) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil || req.URL == nil || req.URL.Host == "" {
		return nil, false
	}
	protocol.SignRequest(req, nil, protocol.SignCredentialFrom(cred), protocol.SignOptions{})
	resp, err := hostHTTPDo(callbackID, req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	body, _ := protocol.ReadAllLimited(resp.Body, 4<<20)
	if resp.StatusCode >= 400 {
		return nil, false
	}
	return body, true
}

func applyCurrentUser(cred *protocol.Credential, body []byte) {
	if cred == nil {
		return
	}
	objs := jsonObjects(body, "user", "result")
	setIfEmpty(&cred.UserID, firstStringField(objs, "user_id", "userId"))
	setIfEmpty(&cred.UserName, firstStringField(objs, "user_name", "userName"))
	setIfEmpty(&cred.DomainID, firstStringField(objs, "domain_id", "domainId"))
}

func applyCallerIdentity(cred *protocol.Credential, body []byte) {
	if cred == nil {
		return
	}
	objs := jsonObjects(body, "result")
	id := firstStringField(objs, "principal_id")
	if id == "" {
		id = firstStringField(objs, "account_id")
	}
	setIfEmpty(&cred.UserID, id)
	setIfEmpty(&cred.UserName, firstStringField(objs, "user_name", "userName"))
}

func jsonObjects(body []byte, nested ...string) []map[string]any {
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil || root == nil {
		return nil
	}
	out := []map[string]any{root}
	for _, key := range nested {
		child, ok := root[key].(map[string]any)
		if !ok {
			continue
		}
		out = append(out, child)
	}
	return out
}

func firstStringField(objs []map[string]any, keys ...string) string {
	for _, key := range keys {
		for _, obj := range objs {
			v, ok := obj[key].(string)
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			if v != "" {
				return v
			}
		}
	}
	return ""
}

func setIfEmpty(dst *string, val string) {
	if dst == nil || strings.TrimSpace(*dst) != "" || strings.TrimSpace(val) == "" {
		return
	}
	*dst = strings.TrimSpace(val)
}

func exchangeCode(callbackID string, lc protocol.LoginConfig, sess *loginSession, code string) (protocol.TokenResponse, error) {
	form := protocol.TokenFormAuthorizationCode(lc, code, sess.Verifier, sess.Port)
	req, err := protocol.NewTokenRequest(lc, form, sess.DPoP)
	if err != nil {
		return protocol.TokenResponse{}, err
	}
	resp, err := hostHTTPDo(callbackID, req)
	if err != nil {
		return protocol.TokenResponse{}, err
	}
	defer resp.Body.Close()
	body, _ := protocol.ReadAllLimited(resp.Body, 4<<20)
	if resp.StatusCode >= 400 {
		return protocol.TokenResponse{}, fmt.Errorf("exchange http=%d %s", resp.StatusCode, truncate(string(body), 200))
	}
	tok, err := protocol.ParseTokenResponse(body)
	if err != nil {
		return protocol.TokenResponse{}, err
	}
	if !tok.HasSTS() || strings.TrimSpace(tok.RefreshToken) == "" {
		return protocol.TokenResponse{}, fmt.Errorf("token response missing DPoP-bound refresh_token")
	}
	return tok, nil
}

func pollTicket(callbackID string, lc protocol.LoginConfig, sess *loginSession, capturedSecret string) (protocol.TokenResponse, error) {
	secret := sess.Secret
	if capturedSecret != "" {
		secret = capturedSecret
	}
	req, err := protocol.NewTicketRequest(lc, sess.TicketID, secret)
	if err != nil {
		return protocol.TokenResponse{}, err
	}
	resp, err := hostHTTPDo(callbackID, req)
	if err != nil {
		return protocol.TokenResponse{}, err
	}
	defer resp.Body.Close()
	body, _ := protocol.ReadAllLimited(resp.Body, 4<<20)
	if resp.StatusCode >= 400 {
		return protocol.TokenResponse{}, fmt.Errorf("ticket http=%d", resp.StatusCode)
	}
	return protocol.ParseTokenResponse(body)
}

func authDataFromCredential(c protocol.Credential, fileName string) pluginapi.AuthData {
	if fileName == "" {
		fileName = protocol.FileNameFor(c)
	}
	raw, _ := protocol.MarshalCredential(c)
	label := c.UserName
	if label == "" {
		label = c.UserID
	}
	if label == "" {
		label = "CodeArts"
	}
	id := fileName
	meta := map[string]any{
		"type":      protocol.Provider,
		"user_id":   c.UserID,
		"user_name": c.UserName,
		// codearts has no ProviderRefreshLead; CPA schedules refresh only when this is positive.
		"refresh_interval_seconds": 600,
	}
	if c.Expiration != "" {
		meta["expires_at"] = c.Expiration
	}
	if c.RefreshToken != "" {
		meta["refresh_token"] = c.RefreshToken
	}
	return pluginapi.AuthData{
		Provider:         protocol.Provider,
		ID:               id,
		FileName:         fileName,
		Label:            label,
		StorageJSON:      raw,
		Metadata:         meta,
		NextRefreshAfter: nextRefreshFromExpiration(c.Expiration),
	}
}

// nextRefreshFromExpiration is a parseable expiration minus 5 minutes.
// An empty or unparseable expiration is now plus 10 minutes.
func nextRefreshFromExpiration(expiration string) time.Time {
	exp, err := time.Parse(time.RFC3339, expiration)
	if err != nil || exp.IsZero() {
		return time.Now().UTC().Add(10 * time.Minute)
	}
	return exp.Add(-5 * time.Minute)
}

func putSession(s *loginSession) {
	sessMu.Lock()
	defer sessMu.Unlock()
	// One in-flight login. CPA cancel does not reach the plugin, so a previous
	// attempt stays until it expires. Huawei then returns its own state, which
	// matches none of those sessions, and the callback is dropped.
	sessions = map[string]*loginSession{s.ID: s}
}

func getSession(id string) *loginSession {
	sessMu.Lock()
	defer sessMu.Unlock()
	gcSessionsLocked()
	return sessions[id]
}

// claimCaptured copies CapturedCode and CapturedSecret. A non-empty code is
// recorded in claimedCodes and cleared before sessMu is released so this poll
// owns it. CapturedSecret is left in place. Do not hold sessMu across hostHTTPDo.
func claimCaptured(sess *loginSession) (code, secret string) {
	sessMu.Lock()
	code, secret = sess.CapturedCode, sess.CapturedSecret
	if code != "" {
		if sess.claimedCodes == nil {
			sess.claimedCodes = map[string]struct{}{}
		}
		sess.claimedCodes[code] = struct{}{}
		sess.CapturedCode = ""
	}
	sessMu.Unlock()
	return code, secret
}

func delSession(id string) {
	sessMu.Lock()
	delete(sessions, id)
	sessMu.Unlock()
}

func gcSessionsLocked() {
	now := time.Now()
	for id, s := range sessions {
		if now.After(s.ExpiresAt) {
			delete(sessions, id)
		}
	}
}

// ingestPollCallback stores callback material carried on this poll.
// A parsed callback with neither state nor ticket_id is for this poll.
// A different state is passed through and is not rewritten onto the poll.
func ingestPollCallback(request []byte, pollState string) {
	if len(request) == 0 || pollState == "" {
		return
	}
	var root map[string]any
	if err := json.Unmarshal(request, &root); err != nil || root == nil {
		return
	}
	if parts := callbackPartsFromPoll(root); parts.Code != "" || parts.Secret != "" {
		bindState := parts.State
		bindTicket := parts.TicketID
		if bindState == "" && bindTicket == "" {
			bindState = pollState
		}
		captureCallback(parts.Code, parts.Secret, bindState, bindTicket)
	}
	if dir := pollAuthDir(root); dir != "" {
		captureAuthDirCode(dir, pollState)
	}
}

func callbackPartsFromPoll(root map[string]any) protocol.CallbackParts {
	sources := []map[string]any{root}
	if meta := nestedObject(root, "Metadata", "metadata"); meta != nil {
		sources = append(sources, meta)
	}
	var parts protocol.CallbackParts
	var parsedURLs []string
	for _, src := range sources {
		for _, key := range []string{"redirect_url", "url", "callback_url", "callback"} {
			raw := pollString(src, key)
			if raw == "" {
				continue
			}
			parsedURLs = append(parsedURLs, raw)
			parts = fillCallbackParts(parts, protocol.ParseCallback(raw))
		}
		code := pollString(src, "code")
		if code == "" {
			continue
		}
		if strings.Contains(code, "://") || strings.Contains(code, "code=") || strings.Contains(code, "secret=") {
			parsedURLs = append(parsedURLs, code)
			parts = fillCallbackParts(parts, protocol.ParseCallback(code))
			continue
		}
		if parts.Code == "" {
			parts.Code = code
		}
	}
	for _, src := range sources {
		secret := pollString(src, "secret")
		if secret == "" || parts.Secret != "" {
			continue
		}
		// Already extracted from a pasted URL; do not layer a second secret.
		if secretInside(parsedURLs, secret) {
			continue
		}
		parts.Secret = secret
		break
	}
	return parts
}

func fillCallbackParts(dst, src protocol.CallbackParts) protocol.CallbackParts {
	if dst.Code == "" {
		dst.Code = src.Code
	}
	if dst.Secret == "" {
		dst.Secret = src.Secret
	}
	if dst.Redirect == "" {
		dst.Redirect = src.Redirect
	}
	if dst.State == "" {
		dst.State = src.State
	}
	if dst.TicketID == "" {
		dst.TicketID = src.TicketID
	}
	return dst
}

func secretInside(urls []string, secret string) bool {
	for _, raw := range urls {
		if strings.Contains(raw, secret) {
			return true
		}
	}
	return false
}

func pollAuthDir(root map[string]any) string {
	if host := nestedObject(root, "Host"); host != nil {
		if dir := pollString(host, "AuthDir"); dir != "" {
			return dir
		}
	}
	if host := nestedObject(root, "host"); host != nil {
		if dir := pollString(host, "auth_dir"); dir != "" {
			return dir
		}
	}
	return ""
}

func nestedObject(m map[string]any, keys ...string) map[string]any {
	if m == nil {
		return nil
	}
	for _, key := range keys {
		child, ok := m[key].(map[string]any)
		if ok && child != nil {
			return child
		}
	}
	return nil
}

func pollString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, ok := m[key].(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

// captureAuthDirCode reads {AuthDir}/.oauth-codearts-{state}.oauth only.
// The state component must be [A-Za-z0-9]. A missing file is not an error.
// A non-empty file state other than this poll is ignored. An error with an
// empty code is not exchanged.
func captureAuthDirCode(authDir, pollState string) {
	if !oauthStateFileToken(pollState) {
		return
	}
	path := filepath.Join(authDir, ".oauth-codearts-"+pollState+".oauth")
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return
	}
	code, fileState, fileErr := parseOAuthCodeFile(raw)
	if fileState != "" && fileState != pollState {
		return
	}
	if fileErr != "" && code == "" {
		return
	}
	if code == "" {
		return
	}
	captureCallback(code, "", pollState, "")
}

func oauthStateFileToken(state string) bool {
	if state == "" {
		return false
	}
	for i := 0; i < len(state); i++ {
		c := state[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func parseOAuthCodeFile(raw []byte) (code, state, oauthErr string) {
	trim := strings.TrimSpace(string(raw))
	if trim == "" {
		return "", "", ""
	}
	if trim[0] == '{' {
		var obj struct {
			Code  string `json:"code"`
			State string `json:"state"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal([]byte(trim), &obj); err == nil {
			return strings.TrimSpace(obj.Code), strings.TrimSpace(obj.State), strings.TrimSpace(obj.Error)
		}
	}
	parts := protocol.ParseCallback(trim)
	return strings.TrimSpace(parts.Code), strings.TrimSpace(parts.State), ""
}

// captureCallback binds a callback to one in-flight session.
// A state or ticketID that hits a session selects only that session. When
// neither hits, exactly one in-flight session still receives the callback.
// Two or more in-flight sessions discard an unmatched state or ticketID.
// A code already claimed by this session is not written to CapturedCode.
// A non-empty CapturedCode or CapturedSecret is not replaced by a different value.
func captureCallback(code, secret, state, ticketID string) *loginSession {
	if code == "" && secret == "" {
		return nil
	}
	sessMu.Lock()
	defer sessMu.Unlock()
	gcSessionsLocked()
	sess := matchCallbackSessionLocked(state, ticketID)
	if sess == nil {
		log.Printf("codearts oauth callback unbound sessions=%d state_len=%d ticket=%t", len(sessions), len(state), ticketID != "")
		return nil
	}
	if code != "" {
		_, claimed := sess.claimedCodes[code]
		if !claimed && (sess.CapturedCode == "" || sess.CapturedCode == code) {
			sess.CapturedCode = code
		}
	}
	if secret != "" && (sess.CapturedSecret == "" || sess.CapturedSecret == secret) {
		sess.CapturedSecret = secret
	}
	return sess
}

// matchCallbackSessionLocked selects the in-flight session for a callback.
// A state equal to a session ID wins. Otherwise a ticketID equal to exactly
// one session's TicketID wins. When neither hits, exactly one in-flight
// session still receives the callback, including a state or ticketID Huawei
// minted. Two or more in-flight sessions discard that unmatched callback.
func matchCallbackSessionLocked(state, ticketID string) *loginSession {
	if state != "" {
		if sess := sessions[state]; sess != nil {
			return sess
		}
	}
	if ticketID != "" {
		var found *loginSession
		matches := 0
		for _, s := range sessions {
			if s.TicketID != ticketID {
				continue
			}
			matches++
			found = s
		}
		if matches == 1 {
			return found
		}
	}
	if len(sessions) != 1 {
		return nil
	}
	for _, s := range sessions {
		return s
	}
	return nil
}

func latestSession() *loginSession {
	sessMu.Lock()
	defer sessMu.Unlock()
	var latest *loginSession
	for _, s := range sessions {
		if latest == nil || s.CreatedAt.After(latest.CreatedAt) {
			latest = s
		}
	}
	return latest
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
