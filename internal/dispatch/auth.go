package dispatch

import (
	"encoding/json"
	"fmt"
	"net/http"
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
		return completeLogin(sess, tok)
	}

	// Ticket GET is not DPoP-bound. Completing on ticket STS would persist
	// sess.DPoP beside credentials whose refresh_token (if any) was issued
	// without that key, and it races the authorization_code exchange.
	tok, err := pollTicket(callbackID, lc, sess, capturedSecret)
	msg := "waiting for Huawei authorization code"
	if capturedSecret != "" {
		msg = "received portal secret; continue Huawei login, then paste the callback URL that contains code="
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
	if fileName == "" {
		fileName = protocol.FileNameFor(next)
	}
	rawNext, err := protocol.MarshalCredential(next)
	if err != nil {
		return errorEnvelope("refresh_error", err.Error(), http.StatusInternalServerError), nil
	}
	_ = hostAuthSave(fileName, rawNext)
	exp, _ := time.Parse(time.RFC3339, next.Expiration)
	nextRefresh := time.Now().UTC().Add(50 * time.Minute)
	if !exp.IsZero() {
		nextRefresh = exp.Add(-5 * time.Minute)
	}
	auth := authDataFromCredential(next, fileName)
	auth.ID = jsonString(request, "AuthID", "auth_id")
	if auth.ID == "" {
		auth.ID = protocol.FileNameFor(next)
	}
	return okEnvelope(pluginapi.AuthRefreshResponse{
		Auth:             auth,
		NextRefreshAfter: nextRefresh,
	})
}

func completeLogin(sess *loginSession, tok protocol.TokenResponse) ([]byte, error) {
	if !tok.HasSTS() || strings.TrimSpace(tok.RefreshToken) == "" {
		return errorEnvelope("login_error", "refusing to persist STS without DPoP-bound refresh_token", http.StatusUnauthorized), nil
	}
	lc := loginConfig()
	cred := protocol.NewCredentialFromToken(tok, sess.Verifier, lc.ClientID, sess.DPoP)
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
	return pluginapi.AuthData{
		Provider:    protocol.Provider,
		ID:          id,
		FileName:    fileName,
		Label:       label,
		StorageJSON: raw,
		Metadata: map[string]any{
			"type":      protocol.Provider,
			"user_id":   c.UserID,
			"user_name": c.UserName,
		},
	}
}

func putSession(s *loginSession) {
	sessMu.Lock()
	defer sessMu.Unlock()
	gcSessionsLocked()
	sessions[s.ID] = s
}

func getSession(id string) *loginSession {
	sessMu.Lock()
	defer sessMu.Unlock()
	gcSessionsLocked()
	return sessions[id]
}

// claimCaptured copies CapturedCode and CapturedSecret. A non-empty code is
// cleared before sessMu is released so this poll owns it. CapturedSecret is
// left in place. Do not hold sessMu across hostHTTPDo.
func claimCaptured(sess *loginSession) (code, secret string) {
	sessMu.Lock()
	code, secret = sess.CapturedCode, sess.CapturedSecret
	if code != "" {
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

// captureCallback binds a callback to one in-flight session.
// A non-empty state selects only sessions[state]. Otherwise a non-empty
// ticketID selects only that TicketID. With neither, it binds only when
// exactly one session is in flight. Any other callback is discarded.
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
		return nil
	}
	if code != "" && (sess.CapturedCode == "" || sess.CapturedCode == code) {
		sess.CapturedCode = code
	}
	if secret != "" && (sess.CapturedSecret == "" || sess.CapturedSecret == secret) {
		sess.CapturedSecret = secret
	}
	return sess
}

func matchCallbackSessionLocked(state, ticketID string) *loginSession {
	if state != "" {
		return sessions[state]
	}
	if ticketID != "" {
		var found *loginSession
		for _, s := range sessions {
			if s.TicketID != ticketID {
				continue
			}
			if found != nil {
				return nil
			}
			found = s
		}
		return found
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
