package dispatch

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dddwill8/codeartsPlugin/internal/protocol"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestLoginFileNameFromCurrentUser(t *testing.T) {
	resetForTest(t)
	const accessKey = "AKID-a"
	var currentHits, callerHits int
	var authz string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case protocol.EpCurrentUser:
			currentHits++
			authz = r.Header.Get("Authorization")
			if r.Method != http.MethodGet {
				http.Error(w, "method", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user_id":"u-live","user_name":"live"}`))
			return
		case protocol.EpCallerIdentity:
			callerHits++
			http.NotFound(w, r)
			return
		}
		if stubAuthorizationCodeExchange(w, r, "", accessKey) {
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	urls := recordClientURLs(srv)

	done := pollCapturedSoleSession(t, srv)
	if done.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("status=%q message=%q", done.Status, done.Message)
	}
	if done.Auth.FileName != "codearts-u-live.json" {
		t.Fatalf("FileName = %q", done.Auth.FileName)
	}
	if currentHits != 1 || !containsString(*urls, srv.URL+protocol.EpCurrentUser) {
		t.Fatalf("current-user hits=%d urls=%v", currentHits, *urls)
	}
	if callerHits != 0 || containsString(*urls, srv.URL+protocol.EpCallerIdentity) {
		t.Fatalf("caller-identity hits=%d urls=%v", callerHits, *urls)
	}
	wantAuth := protocol.SigningAlgorithm + " Access=" + accessKey + ","
	if !strings.HasPrefix(authz, wantAuth) {
		t.Fatalf("current-user Authorization = %q", authz)
	}
	cred, err := protocol.ParseCredential(done.Auth.StorageJSON)
	if err != nil {
		t.Fatal(err)
	}
	if cred.UserID != "u-live" || cred.UserName != "live" {
		t.Fatalf("stored identity = %+v", cred)
	}
	if cred.AccessKeyID != accessKey {
		t.Fatalf("access key = %q", cred.AccessKeyID)
	}
}

func TestLoginFileNameWhenIdentity404(t *testing.T) {
	resetForTest(t)
	const accessKey = "AKID-b"
	hits := map[string]int{}
	var badAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.EpCurrentUser || r.URL.Path == protocol.EpCallerIdentity {
			hits[r.URL.Path]++
			authz := r.Header.Get("Authorization")
			want := protocol.SigningAlgorithm + " Access=" + accessKey + ","
			if r.Method != http.MethodGet || !strings.HasPrefix(authz, want) {
				badAuth = r.Method + " " + authz
			}
			http.NotFound(w, r)
			return
		}
		if stubAuthorizationCodeExchange(w, r, "", accessKey) {
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	urls := recordClientURLs(srv)

	done := pollCapturedSoleSession(t, srv)
	if done.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("status=%q message=%q", done.Status, done.Message)
	}
	wantName := "codearts-" + accessKey + ".json"
	if done.Auth.FileName != wantName {
		t.Fatalf("FileName = %q, want %q", done.Auth.FileName, wantName)
	}
	if hits[protocol.EpCurrentUser] != 1 || hits[protocol.EpCallerIdentity] != 1 {
		t.Fatalf("identity hits = %v urls=%v", hits, *urls)
	}
	if !containsString(*urls, srv.URL+protocol.EpCurrentUser) || !containsString(*urls, srv.URL+protocol.EpCallerIdentity) {
		t.Fatalf("identity URLs = %v", *urls)
	}
	if badAuth != "" {
		t.Fatalf("identity request was not a signed GET: %s", badAuth)
	}
	cred, err := protocol.ParseCredential(done.Auth.StorageJSON)
	if err != nil {
		t.Fatal(err)
	}
	if cred.UserID != "" || cred.AccessKeyID != accessKey {
		t.Fatalf("stored credential = %+v", cred)
	}
}

func TestLoginFileNameSkipsIdentityWhenUserIDSet(t *testing.T) {
	resetForTest(t)
	const accessKey = "AKID-set"
	var identityHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.EpCurrentUser || r.URL.Path == protocol.EpCallerIdentity {
			identityHits++
			http.Error(w, "identity must not be called", http.StatusInternalServerError)
			return
		}
		if stubAuthorizationCodeExchange(w, r, "u-set", accessKey) {
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	urls := recordClientURLs(srv)

	done := pollCapturedSoleSession(t, srv)
	if done.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("status=%q message=%q", done.Status, done.Message)
	}
	if identityHits != 0 || containsString(*urls, protocol.EpCurrentUser) || containsString(*urls, protocol.EpCallerIdentity) {
		t.Fatalf("identity HTTP hits=%d urls=%v", identityHits, *urls)
	}
	if done.Auth.FileName != "codearts-u-set.json" {
		t.Fatalf("FileName = %q", done.Auth.FileName)
	}
}

func TestLoginFileNameParsesNestedIdentity(t *testing.T) {
	var cred protocol.Credential
	applyCurrentUser(&cred, []byte(`{"user":{"userId":"u-nest","userName":"nest","domainId":"dom-1"}}`))
	if cred.UserID != "u-nest" || cred.UserName != "nest" || cred.DomainID != "dom-1" {
		t.Fatalf("nested user = %+v", cred)
	}

	cred = protocol.Credential{UserName: "keep"}
	applyCurrentUser(&cred, []byte(`{"result":{"user_id":"u-res","user_name":"other","domain_id":"dom-2"}}`))
	if cred.UserID != "u-res" || cred.UserName != "keep" || cred.DomainID != "dom-2" {
		t.Fatalf("result nest overwrote token fields: %+v", cred)
	}

	cred = protocol.Credential{}
	applyCallerIdentity(&cred, []byte(`{"account_id":"acct","result":{"principal_id":"prin","user_name":"bob"}}`))
	if cred.UserID != "prin" || cred.UserName != "bob" {
		t.Fatalf("caller identity = %+v", cred)
	}

	cred = protocol.Credential{UserName: "keep"}
	applyCallerIdentity(&cred, []byte(`{"result":{"account_id":"acct-only","user_name":"nope"}}`))
	if cred.UserID != "acct-only" || cred.UserName != "keep" {
		t.Fatalf("account fallback = %+v", cred)
	}

	cred = protocol.Credential{UserID: "already", UserName: "n", DomainID: "d"}
	applyCurrentUser(&cred, []byte(`{"user_id":"other","user_name":"x","domain_id":"y"}`))
	applyCallerIdentity(&cred, []byte(`{"principal_id":"p","user_name":"z"}`))
	if cred.UserID != "already" || cred.UserName != "n" || cred.DomainID != "d" {
		t.Fatalf("filled over existing = %+v", cred)
	}

	cred = protocol.Credential{}
	applyCurrentUser(&cred, []byte(`not-json`))
	applyCallerIdentity(&cred, []byte(`{"result":[]}`))
	if cred.UserID != "" || cred.UserName != "" || cred.DomainID != "" {
		t.Fatalf("tolerant parse wrote %+v", cred)
	}
}

func TestRefreshUnknownFileName(t *testing.T) {
	t.Run("unknown placeholder", func(t *testing.T) {
		resp, identityHits := refreshNamedFile(t, "codearts-unknown.json")
		if resp.Auth.FileName != "codearts-AKZ.json" {
			t.Fatalf("FileName = %q", resp.Auth.FileName)
		}
		if identityHits != 0 {
			t.Fatalf("refresh called identity endpoints %d times", identityHits)
		}
	})
	t.Run("caller name stays", func(t *testing.T) {
		resp, identityHits := refreshNamedFile(t, "codearts-u-refresh.json")
		if resp.Auth.FileName != "codearts-u-refresh.json" {
			t.Fatalf("FileName = %q", resp.Auth.FileName)
		}
		if identityHits != 0 {
			t.Fatalf("refresh called identity endpoints %d times", identityHits)
		}
	})
}

type recordingTransport struct {
	base http.RoundTripper
	urls *[]string
}

func (rt recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	*rt.urls = append(*rt.urls, req.URL.String())
	base := rt.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

func recordClientURLs(srv *httptest.Server) *[]string {
	urls := []string{}
	client := srv.Client()
	client.Transport = recordingTransport{base: client.Transport, urls: &urls}
	return &urls
}

func containsString(vals []string, want string) bool {
	for _, v := range vals {
		if strings.Contains(v, want) {
			return true
		}
	}
	return false
}

func pollCapturedSoleSession(t *testing.T, srv *httptest.Server) pluginapi.AuthLoginPollResponse {
	t.Helper()
	SetEndpoints(endpointOverride{SnapManager: srv.URL, STSHost: srv.URL})
	SetHTTPClient(srv.Client())

	regReq, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("oauth_callback_port: 0\n")})
	_ = mustResult(t, pluginabi.MethodPluginRegister, regReq)
	startRaw := mustResult(t, pluginabi.MethodAuthLoginStart, nil)
	var start pluginapi.AuthLoginStartResponse
	if err := json.Unmarshal(startRaw, &start); err != nil {
		t.Fatal(err)
	}
	if start.State == "" {
		t.Fatal("missing login state")
	}
	sessMu.Lock()
	n := len(sessions)
	sessMu.Unlock()
	if n != 1 {
		t.Fatalf("sessions = %d, want the sole login session", n)
	}
	if captureCallback("auth-code-1", "", "", "") == nil {
		t.Fatal("captureCallback did not bind the sole session")
	}

	pollReq, _ := json.Marshal(map[string]any{"State": start.State})
	raw := mustResult(t, pluginabi.MethodAuthLoginPoll, pollReq)
	var done pluginapi.AuthLoginPollResponse
	if err := json.Unmarshal(raw, &done); err != nil {
		t.Fatal(err)
	}
	return done
}

// stubAuthorizationCodeExchange is the successful token exchange from
// TestAuthLoginPollTicketSTSWithoutRefreshStaysPendingUntilAuthorizationCodeExchange,
// with an explicit user_id and access key.
func stubAuthorizationCodeExchange(w http.ResponseWriter, r *http.Request, userID, accessKeyID string) bool {
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, protocol.EpOAuthTokens) {
		return false
	}
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "auth-code-1" || form.Get("code_verifier") == "" {
		http.Error(w, "bad authorization_code form "+string(body), http.StatusBadRequest)
		return true
	}
	if r.Header.Get("DPoP") == "" {
		http.Error(w, "missing DPoP", http.StatusBadRequest)
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"user_id":%q,"refresh_token":"rt-from-code","credentials":{"access_key_id":%q,"secret_access_key":"skcode","security_token":"st-code","expiration":"2026-12-01T00:00:00Z"}}`, userID, accessKeyID)
	return true
}

func refreshNamedFile(t *testing.T, fileName string) (pluginapi.AuthRefreshResponse, int) {
	t.Helper()
	resetForTest(t)
	dpop, err := protocol.NewDPoPPrivateJWK()
	if err != nil {
		t.Fatal(err)
	}
	prev := protocol.Credential{
		Type:            protocol.Provider,
		UserID:          "",
		AccessKeyID:     "AKZ",
		SecretAccessKey: "skold",
		SecurityToken:   "sts-old",
		RefreshToken:    "rt-old",
		CodeVerifier:    "verifier-1",
		ClientID:        protocol.ClientID,
		DPoPPrivateKey:  map[string]string{"kty": dpop["kty"], "crv": dpop["crv"], "x": dpop["x"], "y": dpop["y"], "d": dpop["d"]},
	}
	identityHits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.EpCurrentUser || r.URL.Path == protocol.EpCallerIdentity {
			identityHits++
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, protocol.EpOAuthTokens) {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "rt-old" || form.Get("client_id") != protocol.ClientID || r.Header.Get("DPoP") == "" {
			http.Error(w, "bad refresh form "+string(body), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"refresh_token":"rt-new","credentials":{"access_key_id":"AKZ","secret_access_key":"sknew","security_token":"sts-new","expiration":"2026-12-01T00:00:00Z"}}`))
	}))
	t.Cleanup(srv.Close)
	SetEndpoints(endpointOverride{STSHost: srv.URL, SnapManager: srv.URL})
	SetHTTPClient(srv.Client())

	storage, err := protocol.MarshalCredential(prev)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := json.Marshal(map[string]any{
		"StorageJSON": storage,
		"FileName":    fileName,
	})
	raw := mustResult(t, pluginabi.MethodAuthRefresh, req)
	var resp pluginapi.AuthRefreshResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	return resp, identityHits
}
