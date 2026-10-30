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
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
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
	// exchanging counts redeemCaptured calls that have claimed a code and have
	// not left exchangeCode. claimCaptured increments it under the same lock
	// that takes the code. endExchange decrements it, and the count reaches
	// zero only after every overlapping redeem has finished.
	// exchangeFailed is set when an exchange rejected the code, no newer code
	// is stored, and no other redeem is still inside exchangeCode.
	// claimCaptured clears both failure flags under the same lock that takes
	// a newer code.
	// saveFailed is set when the code was redeemed but host.auth.save did
	// not write the file. The claimed code stays claimed.
	exchanging     int
	exchangeFailed bool
	saveFailed     bool
}

// loginTerminal is what remains after a session is deleted, until ExpiresAt.
// It records success and a display name only. It must not hold an authorization
// code, secret, refresh token, or STS.
type loginTerminal struct {
	ExpiresAt time.Time
	OK        bool
	Label     string
}

var (
	sessMu          sync.Mutex
	sessions        = map[string]*loginSession{}
	retiredSessions = map[string]time.Time{}
	loginTerminals  = map[string]loginTerminal{}
)

type statusError struct {
	Code   string
	Status int
	Msg    string
}

func (e *statusError) Error() string {
	if e == nil {
		return ""
	}
	return e.Msg
}

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
	auth := authDataFromCredential(c, fileName, raw, true)
	return okEnvelope(pluginapi.AuthParseResponse{
		Handled: true,
		Auth:    auth,
	})
}

func handleLoginStart(_ []byte) ([]byte, error) {
	sess, err := beginLoginSession()
	if err != nil {
		return errorEnvelope("login_error", err.Error(), http.StatusInternalServerError), nil
	}
	lc := loginConfig()
	return okEnvelope(pluginapi.AuthLoginStartResponse{
		Provider:  protocol.Provider,
		URL:       sess.AuthURL,
		State:     sess.ID,
		ExpiresAt: sess.ExpiresAt,
		Metadata: map[string]any{
			"ticket_id":     sess.TicketID,
			"callback_path": protocol.RedirectURI(lc, sess.Port),
		},
	})
}

// beginLoginSession builds the one in-flight login: PKCE, DPoP, and putSession.
// The state stays in the plugin. It is not written to CPA's OAuth session table.
// A later call replaces that session. The previous authorization code is not copied.
func beginLoginSession() (*loginSession, error) {
	cfg := currentConfig()
	lc := loginConfig()
	ticketID, err := protocol.RandomHex(16)
	if err != nil {
		return nil, err
	}
	secret, err := protocol.RandomHex(16)
	if err != nil {
		return nil, err
	}
	verifier, challenge, err := protocol.PKCE()
	if err != nil {
		return nil, err
	}
	dpop, err := protocol.NewDPoPPrivateJWK()
	if err != nil {
		return nil, err
	}
	port := cfg.CallbackPort
	if port <= 0 {
		port = 18080
	}
	state, err := protocol.RandomHex(16)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	sess := &loginSession{
		ID:        state,
		TicketID:  ticketID,
		Secret:    secret,
		Verifier:  verifier,
		DPoP:      dpop,
		Port:      port,
		AuthURL:   protocol.BuildAuthorizeURL(lc, ticketID, challenge, port),
		CreatedAt: now,
		ExpiresAt: now.Add(15 * time.Minute),
	}
	putSession(sess)
	ensureCallbackListener(cfg)
	return sess, nil
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
	// The listener does not exchange; this poll does, once.
	ingestPollCallback(request, state)
	lc := loginConfig()
	callbackID := jsonString(request, "host_callback_id", "HostCallbackID")
	out := redeemCaptured(sess, callbackID)
	if out.Hard != nil {
		return errorEnvelope(out.Hard.Code, out.Hard.Msg, out.Hard.Status), nil
	}
	if out.SaveFailed {
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusError,
			Message: "credential file was not written",
		})
	}
	if out.Exchanged {
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusSuccess,
			Message: "CodeArts login complete",
			Auth:    out.Auth,
		})
	}
	// Ticket GET races an in-flight authorization_code exchange. A burned
	// code stays on the rejection text; it must not look uncaptured.
	if out.Busy {
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusPending,
			Message: "exchanging authorization code",
		})
	}
	if out.Rejected || out.PriorFailure {
		return okEnvelope(pluginapi.AuthLoginPollResponse{
			Status:  pluginapi.AuthLoginStatusPending,
			Message: rejectedPollMessage(out.RejectReason),
		})
	}

	// Ticket GET is not DPoP-bound. Completing on ticket STS would persist
	// sess.DPoP beside credentials whose refresh_token (if any) was issued
	// without that key, and it races the authorization_code exchange.
	capturedSecret := out.Secret
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
		return errorEnvelope("refresh_error", "credential missing client_id, refresh_token, or DPoP private key", http.StatusBadGateway), nil
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
		code := stsErrorCode(body)
		log.Printf("codearts sts refresh http=%d error=%s", resp.StatusCode, code)
		// CPA treats HTTP 401 as a terminal unauthorized failure and stops
		// scheduling. STS 400 stays 400 so invalid_grant keeps backing off.
		// Every other failure is 502, which CPA retries.
		status := http.StatusBadGateway
		if resp.StatusCode == http.StatusBadRequest {
			status = http.StatusBadRequest
		}
		return errorEnvelope("refresh_error", fmt.Sprintf("sts refresh http=%d error=%s", resp.StatusCode, code), status), nil
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
	// Keep CPA-owned keys from the stored file (prefix, priority, proxy_url, ...).
	auth := authDataFromCredential(next, fileName, raw, false)
	if len(auth.StorageJSON) == 0 {
		return errorEnvelope("refresh_error", "encode credential", http.StatusInternalServerError), nil
	}
	if err := hostAuthSave(fileName, auth.StorageJSON); err != nil {
		// The old refresh_token is already spent. The returned Auth is now the
		// only copy of the new one; CPA still persists it from this response.
		log.Printf("codearts refresh auth save failed")
	}
	auth.ID = jsonString(request, "AuthID", "auth_id")
	if auth.ID == "" {
		auth.ID = protocol.FileNameFor(next)
	}
	return okEnvelope(pluginapi.AuthRefreshResponse{
		Auth:             auth,
		NextRefreshAfter: auth.NextRefreshAfter,
	})
}

// redeemOutcome is one attempt to exchange a captured authorization code.
// Poll, the management paste, and the management status query all use it.
// claimCaptured makes the same code exchange at most once.
type redeemOutcome struct {
	Secret       string
	Exchanged    bool
	Rejected     bool
	RejectReason string
	Auth         pluginapi.AuthData
	Label        string
	Hard         *statusError
	Busy         bool
	// PriorFailure means an earlier exchange rejected the code and no newer
	// code is waiting. This call did not exchange.
	PriorFailure bool
	// SaveFailed means the code was redeemed and host.auth.save failed.
	// No success terminal was written.
	SaveFailed bool
}

func redeemCaptured(sess *loginSession, callbackID string) redeemOutcome {
	code, secret := claimCaptured(sess)
	out := redeemOutcome{Secret: secret}
	if code == "" {
		out.Busy = sessionBusy(sess)
		out.SaveFailed = sessionSaveFailed(sess)
		out.PriorFailure = sessionExchangeFailed(sess)
		return out
	}
	// claimCaptured already counted this redeem. endExchange runs on every
	// return, including a rejected code, and only drops this call's count.
	defer endExchange(sess)
	tok, err := exchangeCode(callbackID, loginConfig(), sess, code)
	if err != nil {
		// The code was claimed before exchange. Do not clear CapturedCode
		// again: captureCallback may have stored a newer code during the
		// HTTP call, and that code must remain.
		out.Rejected = true
		out.RejectReason = err.Error()
		markExchangeFailedIfNoNewerCode(sess)
		return out
	}
	auth, hard := finishLogin(sess, tok, callbackID)
	if hard != nil {
		if sessionSaveFailed(sess) {
			out.SaveFailed = true
			return out
		}
		out.Hard = hard
		return out
	}
	out.Exchanged = true
	out.Auth = auth
	out.Label = auth.Label
	return out
}

// finishLogin writes codearts-<user>.json through host.auth.save and drops the
// session. host.auth.save is the same call auth.refresh uses to hand the
// credential to CPA. A display-name terminal remains until ExpiresAt.
// A save error leaves the session in place and does not record success.
// The claimed code is not put back, so it cannot be redeemed twice.
func finishLogin(sess *loginSession, tok protocol.TokenResponse, callbackID string) (pluginapi.AuthData, *statusError) {
	if !tok.HasSTS() || strings.TrimSpace(tok.RefreshToken) == "" {
		return pluginapi.AuthData{}, &statusError{
			Code:   "login_error",
			Status: http.StatusUnauthorized,
			Msg:    "refusing to persist STS without DPoP-bound refresh_token",
		}
	}
	lc := loginConfig()
	cred := protocol.NewCredentialFromToken(tok, sess.Verifier, lc.ClientID, sess.DPoP)
	if strings.TrimSpace(cred.UserID) == "" {
		fillCredentialIdentity(callbackID, lc, &cred)
	}
	fileName := protocol.FileNameFor(cred)
	auth := authDataFromCredential(cred, fileName, loadExistingAuthJSON(fileName), false)
	if len(auth.StorageJSON) == 0 {
		return pluginapi.AuthData{}, &statusError{
			Code:   "login_error",
			Status: http.StatusInternalServerError,
			Msg:    "encode credential",
		}
	}
	if err := hostAuthSave(fileName, auth.StorageJSON); err != nil {
		log.Printf("codearts auth save failed")
		markSaveFailed(sess)
		return pluginapi.AuthData{}, &statusError{
			Code:   "login_error",
			Status: http.StatusBadGateway,
			Msg:    "认证文件没有写入。",
		}
	}
	rememberTerminal(sess, auth.Label)
	delSession(sess.ID)
	return auth, nil
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

func rejectedPollMessage(reason string) string {
	const tail = "; paste a new callback URL or reset login"
	if reason == "" {
		return "authorization code rejected" + tail
	}
	return "authorization code rejected: " + reason + tail
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

func authDataFromCredential(c protocol.Credential, fileName string, original []byte, reuseSchedule bool) pluginapi.AuthData {
	if fileName == "" {
		fileName = protocol.FileNameFor(c)
	}
	raw, err := protocol.MergeCredential(original, c)
	if err != nil {
		raw, _ = protocol.MarshalCredential(c)
	}
	when, secs := refreshSchedule(time.Now().UTC(), c.Expiration, c.UpdatedAt.Time())
	if !reuseSchedule && !when.IsZero() {
		raw = stampNextRefresh(raw, when)
	}
	label := c.UserName
	if label == "" {
		label = c.UserID
	}
	if label == "" {
		label = "CodeArts"
	}
	meta := map[string]any{
		"type":      protocol.Provider,
		"user_id":   c.UserID,
		"user_name": c.UserName,
		// codearts has no ProviderRefreshLead. CPA treats this one value as
		// both the refresh period and the lead. It must be half this
		// credential's lifetime, not the seconds until NextRefreshAfter.
		// Zero means the lifetime is unknown, so CPA does not refresh.
		"refresh_interval_seconds": secs,
	}
	if !c.UpdatedAt.IsZero() {
		meta["last_refresh"] = c.UpdatedAt.Time().Format(time.RFC3339Nano)
	}
	if c.Expiration != "" {
		meta["expires_at"] = c.Expiration
	}
	if c.RefreshToken != "" {
		meta["refresh_token"] = c.RefreshToken
	}
	auth := pluginapi.AuthData{
		Provider:         protocol.Provider,
		ID:               fileName,
		FileName:         fileName,
		Label:            label,
		StorageJSON:      raw,
		Metadata:         meta,
		NextRefreshAfter: when,
	}
	applyOperatorFields(&auth, raw)
	return auth
}

const refreshRetryFloor = 2 * time.Minute

// refreshSchedule is the next STS refresh and the CPA interval.
// The interval is half of expiration-issued. CPA uses that single number as
// both the period and the lead, so it must stay strictly below the lifetime.
// A healthy token is refreshed at expiration minus that half. A token already
// inside the second half, or an expired one, waits two minutes. The result is
// never due already: a past NextRefreshAfter makes CPA refresh, rewrite the
// auth file, and reload it about a second later. An unknown lifetime returns
// a zero time and a zero interval, and CPA does not refresh.
func refreshSchedule(now time.Time, expiration string, issued time.Time) (time.Time, int) {
	now = now.UTC()
	exp, expOK := parseRFC3339(expiration)
	if !expOK {
		return time.Time{}, 0
	}
	interval, ok := refreshInterval(exp, issued.UTC())
	if !ok {
		return time.Time{}, 0
	}
	at := now.Add(refreshRetryFloor)
	if exp.After(now) && exp.Sub(now) > interval {
		at = exp.Add(-interval)
	}
	return at, int(interval / time.Second)
}

// refreshInterval is half the STS lifetime, truncated to whole seconds.
// It is false when the half would be zero or at least as long as the lifetime.
func refreshInterval(exp, issued time.Time) (time.Duration, bool) {
	if exp.IsZero() || issued.IsZero() || !exp.After(issued) {
		return 0, false
	}
	life := exp.Sub(issued)
	secs := int(life / 2 / time.Second)
	if secs < 1 {
		return 0, false
	}
	interval := time.Duration(secs) * time.Second
	if interval >= life {
		return 0, false
	}
	return interval, true
}

// stsErrorCode is the OAuth error code from an STS failure body.
// The raw body is not returned: CPA treats the substrings "status 401" and
// "401 unauthorized" as a terminal auth failure.
func stsErrorCode(body []byte) string {
	var obj struct {
		Error     string `json:"error"`
		ErrorCode string `json:"error_code"`
	}
	if json.Unmarshal(body, &obj) != nil {
		return "unknown"
	}
	code := strings.TrimSpace(obj.Error)
	if code == "" {
		code = strings.TrimSpace(obj.ErrorCode)
	}
	if code == "" {
		return "unknown"
	}
	lower := strings.ToLower(code)
	if strings.Contains(lower, "status 401") || strings.Contains(lower, "401 unauthorized") {
		return "unknown"
	}
	if len(code) > 80 {
		code = code[:80]
	}
	return code
}

func parseRFC3339(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if ts, err := time.Parse(layout, s); err == nil && !ts.IsZero() {
			return ts.UTC(), true
		}
	}
	return time.Time{}, false
}

func storedStringField(raw []byte, key string) string {
	var obj map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &obj) != nil {
		return ""
	}
	field, ok := obj[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(field, &s) != nil {
		return ""
	}
	return s
}

func stampNextRefresh(raw []byte, at time.Time) []byte {
	var obj map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &obj) != nil || obj == nil {
		return raw
	}
	obj["next_refresh_after"] = at.UTC().Format(time.RFC3339Nano)
	out, err := json.Marshal(obj)
	if err != nil {
		return raw
	}
	return out
}

// applyOperatorFields copies prefix, proxy_url, and a true disabled flag onto
// the auth CPA keeps in memory. A missing disabled key stays false so a new
// file does not gain disabled:false. The JSON itself is left unchanged.
func applyOperatorFields(auth *pluginapi.AuthData, raw []byte) {
	if auth == nil || len(raw) == 0 {
		return
	}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		return
	}
	if p, ok := obj["prefix"].(string); ok {
		p = strings.Trim(strings.TrimSpace(p), "/")
		if p != "" && !strings.Contains(p, "/") {
			auth.Prefix = p
		}
	}
	if p, ok := obj["proxy_url"].(string); ok {
		if p = strings.TrimSpace(p); p != "" {
			auth.ProxyURL = p
		}
	}
	disabled, ok := obj["disabled"].(bool)
	if !ok || !disabled {
		return
	}
	auth.Disabled = true
	if auth.Metadata == nil {
		auth.Metadata = map[string]any{}
	}
	auth.Metadata["disabled"] = true
}

// loadExistingAuthJSON reads the auth file this login is about to replace.
// A miss, including no host callback, writes a new file and does not fail login.
// Only the exact file name is used, so another CodeArts account is not copied.
func loadExistingAuthJSON(fileName string) []byte {
	fileName = strings.TrimSpace(fileName)
	if fileName == "" || currentCaller() == nil {
		return nil
	}
	listed, err := callHost(pluginabi.MethodHostAuthList, map[string]any{})
	if err != nil {
		return nil
	}
	var list struct {
		Files []struct {
			Name      string `json:"name"`
			AuthIndex string `json:"auth_index"`
			Path      string `json:"path"`
		} `json:"files"`
	}
	if json.Unmarshal(listed, &list) != nil {
		return nil
	}
	var index string
	for _, file := range list.Files {
		name := strings.TrimSpace(file.Name)
		if name != fileName && filepath.Base(strings.TrimSpace(file.Path)) != fileName {
			continue
		}
		index = strings.TrimSpace(file.AuthIndex)
		if index != "" {
			break
		}
	}
	if index == "" {
		return nil
	}
	got, err := callHost(pluginabi.MethodHostAuthGet, map[string]any{"auth_index": index})
	if err != nil {
		return nil
	}
	var resp struct {
		JSON json.RawMessage `json:"json"`
	}
	if json.Unmarshal(got, &resp) != nil || len(bytesTrim(resp.JSON)) == 0 {
		return nil
	}
	return append([]byte(nil), resp.JSON...)
}

func bytesTrim(raw []byte) []byte {
	return []byte(strings.TrimSpace(string(raw)))
}

func putSession(s *loginSession) {
	sessMu.Lock()
	defer sessMu.Unlock()
	gcSessionsLocked()
	// One in-flight login. A new attempt replaces the previous session.
	// The previous authorization code stays on the old object and is not copied.
	// Its id is retired so a later paste of that id cannot land on the new session.
	for _, old := range sessions {
		if old != nil && old.ID != s.ID {
			retireSessionLocked(old)
		}
	}
	if sessions == nil {
		sessions = map[string]*loginSession{}
	}
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
// owns it. exchangeFailed and saveFailed from the previous code are cleared
// under that same lock, and exchanging is incremented there. A newer code
// another redeem has already claimed is therefore busy before this function
// returns, even though CapturedCode is empty again. CapturedSecret is left
// in place. Do not hold sessMu across hostHTTPDo.
func claimCaptured(sess *loginSession) (code, secret string) {
	sessMu.Lock()
	code, secret = sess.CapturedCode, sess.CapturedSecret
	if code != "" {
		if sess.claimedCodes == nil {
			sess.claimedCodes = map[string]struct{}{}
		}
		sess.claimedCodes[code] = struct{}{}
		sess.CapturedCode = ""
		sess.exchangeFailed = false
		sess.saveFailed = false
		sess.exchanging++
	}
	sessMu.Unlock()
	return code, secret
}

func delSession(id string) {
	sessMu.Lock()
	if s := sessions[id]; s != nil {
		retireSessionLocked(s)
	}
	delete(sessions, id)
	sessMu.Unlock()
}

func rememberTerminal(sess *loginSession, label string) {
	if sess == nil || sess.ID == "" {
		return
	}
	sessMu.Lock()
	defer sessMu.Unlock()
	if loginTerminals == nil {
		loginTerminals = map[string]loginTerminal{}
	}
	loginTerminals[sess.ID] = loginTerminal{
		ExpiresAt: sess.ExpiresAt,
		OK:        true,
		Label:     label,
	}
}

func terminalOf(id string) (loginTerminal, bool) {
	sessMu.Lock()
	defer sessMu.Unlock()
	gcSessionsLocked()
	term, ok := loginTerminals[id]
	return term, ok
}

func retireSessionLocked(s *loginSession) {
	if s == nil || s.ID == "" {
		return
	}
	until := time.Now().Add(15 * time.Minute)
	if s.ExpiresAt.After(until) {
		until = s.ExpiresAt
	}
	if retiredSessions == nil {
		retiredSessions = map[string]time.Time{}
	}
	if prev, ok := retiredSessions[s.ID]; ok && prev.After(until) {
		return
	}
	retiredSessions[s.ID] = until
}

func isRetiredSession(id string) bool {
	if id == "" {
		return false
	}
	sessMu.Lock()
	defer sessMu.Unlock()
	// A session put back after a later login replaced it is in flight again.
	if sessions[id] != nil {
		return false
	}
	until, ok := retiredSessions[id]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(retiredSessions, id)
		return false
	}
	return true
}

func gcSessionsLocked() {
	now := time.Now()
	for id, s := range sessions {
		if now.After(s.ExpiresAt) {
			retireSessionLocked(s)
			delete(sessions, id)
		}
	}
	for id, until := range retiredSessions {
		if now.After(until) {
			delete(retiredSessions, id)
		}
	}
	for id, term := range loginTerminals {
		if now.After(term.ExpiresAt) {
			delete(loginTerminals, id)
		}
	}
}

func clearLoginState() {
	sessMu.Lock()
	sessions = map[string]*loginSession{}
	retiredSessions = map[string]time.Time{}
	loginTerminals = map[string]loginTerminal{}
	sessMu.Unlock()
}

// endExchange drops the count claimCaptured added for this redeem. It does not
// clear a count another redeem still holds.
func endExchange(sess *loginSession) {
	if sess == nil {
		return
	}
	sessMu.Lock()
	if sess.exchanging > 0 {
		sess.exchanging--
	}
	sessMu.Unlock()
}

// markExchangeFailedIfNoNewerCode sets exchangeFailed only when no newer
// authorization code is stored and this session is not still inside another
// redeem. An empty CapturedCode is not enough: the other redeem may already
// have claimed that code. This call still holds one count, so a count above
// one means that other redeem. The check and the write share sessMu.
func markExchangeFailedIfNoNewerCode(sess *loginSession) {
	sessMu.Lock()
	if sess.CapturedCode == "" && sess.exchanging <= 1 {
		sess.exchangeFailed = true
	}
	sessMu.Unlock()
}

func markSaveFailed(sess *loginSession) {
	sessMu.Lock()
	sess.saveFailed = true
	sessMu.Unlock()
}

func sessionSaveFailed(sess *loginSession) bool {
	sessMu.Lock()
	defer sessMu.Unlock()
	return sess.saveFailed
}

// sessionSaveBlocked is a redeemed code whose file was not written, with no
// newer code waiting and no exchange in flight.
func sessionSaveBlocked(sess *loginSession) bool {
	if sess == nil {
		return false
	}
	sessMu.Lock()
	defer sessMu.Unlock()
	return sess.saveFailed && sess.CapturedCode == "" && sess.exchanging == 0
}

func sessionBusy(sess *loginSession) bool {
	sessMu.Lock()
	defer sessMu.Unlock()
	return sess.exchanging > 0
}

func sessionExchangeFailed(sess *loginSession) bool {
	sessMu.Lock()
	defer sessMu.Unlock()
	return sess.exchangeFailed && sess.CapturedCode == ""
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
			sess.exchangeFailed = false
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
	// A state that belonged to a replaced or expired session must not be
	// written onto the session that replaced it.
	if state != "" {
		if until, ok := retiredSessions[state]; ok && time.Now().Before(until) {
			return nil
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
