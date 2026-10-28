package dispatch

import (
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/dddwill8/codeartsPlugin/internal/protocol"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// keepSession returns a function that puts id back after a later login start
// removes it. Use it only when a test needs two sessions on purpose.
func keepSession(t *testing.T, id string) func() {
	t.Helper()
	sessMu.Lock()
	s := sessions[id]
	sessMu.Unlock()
	if s == nil {
		t.Fatalf("missing session %s", id)
	}
	return func() {
		sessMu.Lock()
		if sessions == nil {
			sessions = map[string]*loginSession{}
		}
		sessions[id] = s
		sessMu.Unlock()
	}
}

func resetForTest(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		clearLoginState()
		clearResourceBase()
		SetEndpoints(endpointOverride{})
		SetCaller(nil)
		SetHTTPClient(nil)
		setConfig(defaultConfig())
		stopCallbackListener()
	})
	clearLoginState()
	clearResourceBase()
	SetEndpoints(endpointOverride{})
	SetCaller(nil)
	SetHTTPClient(nil)
	setConfig(defaultConfig())
	stopCallbackListener()
}

func mustHandle(t *testing.T, method string, request []byte) envelope {
	t.Helper()
	raw, err := Handle(method, request)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v\n%s", err, raw)
	}
	return env
}

func mustResult(t *testing.T, method string, request []byte) json.RawMessage {
	t.Helper()
	env := mustHandle(t, method, request)
	if !env.OK {
		msg := ""
		if env.Error != nil {
			msg = env.Error.Code + ": " + env.Error.Message
		}
		t.Fatalf("%s not ok: %s\n%s", method, msg, request)
	}
	return env.Result
}

func resultMap(t *testing.T, method string, request []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(mustResult(t, method, request), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestPluginRegisterDeclaresRequiredCapabilitiesAndConfigFields(t *testing.T) {
	resetForTest(t)
	req, err := json.Marshal(lifecycleRequest{
		ConfigYAML:    []byte("oauth_callback_port: 0\nbenefit_auto_claim: true\n"),
		SchemaVersion: pluginabi.SchemaVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := mustResult(t, pluginabi.MethodPluginRegister, req)
	var reg registration
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatal(err)
	}
	if reg.SchemaVersion != pluginabi.SchemaVersion {
		t.Fatalf("schema_version = %d", reg.SchemaVersion)
	}
	if reg.Metadata.Name != protocol.PluginID {
		t.Fatalf("metadata name = %q", reg.Metadata.Name)
	}
	caps := reg.Capabilities
	if !caps.ModelRegistrar || !caps.ModelProvider || !caps.AuthProvider || !caps.Executor {
		t.Fatalf("capabilities = %+v", caps)
	}
	if !caps.ManagementAPI {
		t.Fatal("management_api should be on so a remote panel can submit the loopback callback")
	}
	if caps.ExecutorModelScope != pluginapi.ExecutorModelScopeBoth {
		t.Fatalf("executor_model_scope = %q", caps.ExecutorModelScope)
	}
	if len(caps.ExecutorInputFormats) == 0 || caps.ExecutorInputFormats[0] != "chat-completions" {
		t.Fatalf("executor_input_formats = %v", caps.ExecutorInputFormats)
	}
	names := map[string]bool{}
	for _, f := range reg.Metadata.ConfigFields {
		names[f.Name] = true
	}
	for _, want := range []string{"oauth_callback_host", "oauth_callback_port", "oauth_callback_path", "benefit_auto_claim"} {
		if !names[want] {
			t.Fatalf("missing ConfigField %s in %+v", want, reg.Metadata.ConfigFields)
		}
	}
	if currentConfig().CallbackPort != 0 {
		t.Fatalf("oauth_callback_port not applied: %+v", currentConfig())
	}

	again := mustResult(t, pluginabi.MethodPluginReconfigure, req)
	var reg2 registration
	if err := json.Unmarshal(again, &reg2); err != nil {
		t.Fatal(err)
	}
	if !reg2.Capabilities.AuthProvider {
		t.Fatal("reconfigure dropped auth_provider")
	}
}

func TestAuthLoginStartAndPollPendingWithoutTicket(t *testing.T) {
	resetForTest(t)
	ticketHits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/v1/login/ticket") {
			ticketHits++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user_id":"","refresh_token":"","credentials":{}}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	SetEndpoints(endpointOverride{SnapManager: srv.URL})
	SetHTTPClient(srv.Client())

	regReq, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("oauth_callback_port: 0\n")})
	_ = mustResult(t, pluginabi.MethodPluginRegister, regReq)

	startRaw := mustResult(t, pluginabi.MethodAuthLoginStart, nil)
	var start pluginapi.AuthLoginStartResponse
	if err := json.Unmarshal(startRaw, &start); err != nil {
		t.Fatal(err)
	}
	if start.Provider != protocol.Provider {
		t.Fatalf("provider = %q", start.Provider)
	}
	if start.State == "" {
		t.Fatal("missing opaque state")
	}
	if start.ExpiresAt.IsZero() || !start.ExpiresAt.After(time.Now()) {
		t.Fatalf("ExpiresAt = %s", start.ExpiresAt)
	}
	u, err := url.Parse(start.URL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "https" || u.Host != "codearts.huaweicloud.com" || u.Path != "/portal/authorize" {
		t.Fatalf("authorize url = %s", start.URL)
	}
	q := u.Query()
	if q.Get("client_id") != "codearts-agent" {
		t.Fatalf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("code_challenge") == "" {
		t.Fatal("missing code_challenge")
	}
	if q.Get("ticket_id") == "" {
		t.Fatal("missing ticket_id")
	}

	pollReq, _ := json.Marshal(map[string]any{"State": start.State})
	pollRaw := mustResult(t, pluginabi.MethodAuthLoginPoll, pollReq)
	var poll pluginapi.AuthLoginPollResponse
	if err := json.Unmarshal(pollRaw, &poll); err != nil {
		t.Fatal(err)
	}
	if poll.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("poll status = %q message=%q (want pending)", poll.Status, poll.Message)
	}
	if poll.Auth.StorageJSON != nil && len(poll.Auth.StorageJSON) > 0 {
		t.Fatalf("pending poll returned auth: %s", poll.Auth.StorageJSON)
	}
	if ticketHits == 0 {
		t.Fatal("ticket endpoint was not polled")
	}
}

func TestAuthLoginPollTicketSTSWithoutRefreshStaysPendingUntilAuthorizationCodeExchange(t *testing.T) {
	resetForTest(t)
	var (
		ticketHits int
		tokenHits  int
		gotGrant   string
		gotCode    string
		gotDPoP    string
		gotClient  string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/v1/login/ticket") {
			ticketHits++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user_id":"legacy-user","user_name":"legacy","credential":{"access":"AKTICKET","secret":"skticket","securitytoken":"st-ticket","expires_at":"2026-09-03T00:00:00Z"}}`))
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/oauth2/tokens") {
			tokenHits++
			gotDPoP = r.Header.Get("DPoP")
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			gotGrant = form.Get("grant_type")
			gotCode = form.Get("code")
			gotClient = form.Get("client_id")
			if form.Get("grant_type") != "authorization_code" || form.Get("code") != "auth-code-1" || form.Get("code_verifier") == "" {
				http.Error(w, "bad authorization_code form "+string(body), http.StatusBadRequest)
				return
			}
			if r.Header.Get("DPoP") == "" {
				http.Error(w, "missing DPoP", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user_id":"u-code","user_name":"alice","refresh_token":"rt-from-code","credentials":{"access_key_id":"AKCODE","secret_access_key":"skcode","security_token":"st-code","expiration":"2026-12-01T00:00:00Z"}}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	SetEndpoints(endpointOverride{SnapManager: srv.URL, STSHost: srv.URL})
	SetHTTPClient(srv.Client())

	regReq, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("oauth_callback_port: 0\n")})
	_ = mustResult(t, pluginabi.MethodPluginRegister, regReq)
	startRaw := mustResult(t, pluginabi.MethodAuthLoginStart, nil)
	var start pluginapi.AuthLoginStartResponse
	if err := json.Unmarshal(startRaw, &start); err != nil {
		t.Fatal(err)
	}
	sess := latestSession()
	if sess == nil || sess.DPoP["d"] == "" {
		t.Fatal("login session missing DPoP private key")
	}
	wantD := sess.DPoP["d"]

	pollReq, _ := json.Marshal(map[string]any{"State": start.State})
	pollRaw := mustResult(t, pluginabi.MethodAuthLoginPoll, pollReq)
	var poll pluginapi.AuthLoginPollResponse
	if err := json.Unmarshal(pollRaw, &poll); err != nil {
		t.Fatal(err)
	}
	if poll.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("ticket STS without refresh_token completed login: status=%q message=%q", poll.Status, poll.Message)
	}
	if !strings.Contains(poll.Message, "refresh_token") && !strings.Contains(poll.Message, "authorization code") {
		t.Fatalf("pending message = %q", poll.Message)
	}
	if ticketHits == 0 {
		t.Fatal("ticket endpoint was not polled")
	}
	if tokenHits != 0 {
		t.Fatalf("authorization_code exchange ran before callback, hits=%d", tokenHits)
	}

	parts := applyPastedCallback("http://127.0.0.1:18080/oauth/callback?code=auth-code-1")
	if parts.Code != "auth-code-1" {
		t.Fatalf("pasted code = %q", parts.Code)
	}

	doneRaw := mustResult(t, pluginabi.MethodAuthLoginPoll, pollReq)
	var done pluginapi.AuthLoginPollResponse
	if err := json.Unmarshal(doneRaw, &done); err != nil {
		t.Fatal(err)
	}
	if done.Status != pluginapi.AuthLoginStatusSuccess {
		t.Fatalf("after pasted code: status=%q message=%q", done.Status, done.Message)
	}
	if tokenHits == 0 {
		t.Fatal("pasted code did not POST /v1/oauth2/tokens")
	}
	if gotGrant != "authorization_code" {
		t.Fatalf("grant_type = %q", gotGrant)
	}
	if gotCode != "auth-code-1" {
		t.Fatalf("code = %q", gotCode)
	}
	if gotClient != protocol.ClientID {
		t.Fatalf("client_id = %q", gotClient)
	}
	if gotDPoP == "" {
		t.Fatal("authorization_code exchange missing DPoP header")
	}
	cred, err := protocol.ParseCredential(done.Auth.StorageJSON)
	if err != nil {
		t.Fatal(err)
	}
	if cred.RefreshToken != "rt-from-code" {
		t.Fatalf("refresh_token = %q", cred.RefreshToken)
	}
	if cred.ClientID != protocol.ClientID {
		t.Fatalf("persisted client_id = %q", cred.ClientID)
	}
	if cred.DPoPPrivateKey["d"] != wantD {
		t.Fatalf("dpop.d = %q want %q", cred.DPoPPrivateKey["d"], wantD)
	}
	if cred.AccessKeyID != "AKCODE" || cred.SecurityToken != "st-code" {
		t.Fatalf("persisted STS = %+v", cred)
	}
}

func TestAuthRefreshRotatesSTSViaStub(t *testing.T) {
	resetForTest(t)
	dpop, err := protocol.NewDPoPPrivateJWK()
	if err != nil {
		t.Fatal(err)
	}
	prev := protocol.Credential{
		Type:            protocol.Provider,
		UserID:          "u-refresh",
		AccessKeyID:     "AKOLD",
		SecretAccessKey: "skold",
		SecurityToken:   "sts-old",
		RefreshToken:    "rt-old",
		CodeVerifier:    "verifier-1",
		ClientID:        protocol.ClientID,
		DPoPPrivateKey:  map[string]string{"kty": dpop["kty"], "crv": dpop["crv"], "x": dpop["x"], "y": dpop["y"], "d": dpop["d"]},
	}
	gotDPoP := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/v1/oauth2/tokens") {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("DPoP") != "" {
			gotDPoP = true
		}
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "rt-old" {
			http.Error(w, "bad form "+string(body), http.StatusBadRequest)
			return
		}
		if form.Get("client_id") != protocol.ClientID {
			http.Error(w, "bad client_id", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user_id":"u-refresh","refresh_token":"rt-new","credentials":{"access_key_id":"AKNEW","secret_access_key":"sknew","security_token":"sts-new","expiration":"2026-12-01T00:00:00Z"}}`))
	}))
	t.Cleanup(srv.Close)
	SetEndpoints(endpointOverride{STSHost: srv.URL})
	SetHTTPClient(srv.Client())

	storage, err := protocol.MarshalCredential(prev)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := json.Marshal(map[string]any{
		"StorageJSON": storage,
		"FileName":    "codearts-u-refresh.json",
	})
	raw := mustResult(t, pluginabi.MethodAuthRefresh, req)
	var resp pluginapi.AuthRefreshResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if !gotDPoP {
		t.Fatal("STS refresh missing DPoP header")
	}
	next, err := protocol.ParseCredential(resp.Auth.StorageJSON)
	if err != nil {
		t.Fatal(err)
	}
	if next.ClientID != protocol.ClientID {
		t.Fatalf("client_id = %q", next.ClientID)
	}
	if next.DPoPPrivateKey["d"] != dpop["d"] {
		t.Fatal("dpop d was not persisted")
	}
	if next.RefreshToken != "rt-new" || next.AccessKeyID != "AKNEW" || next.SecurityToken != "sts-new" {
		t.Fatalf("refresh not applied: %+v", next)
	}
}

func TestExecutorHandlePostsSignedBenefitChat(t *testing.T) {
	resetForTest(t)
	var gotAuth, gotMaas, gotModelID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMaas = r.Header.Get("maas_type")
		gotModelID = r.Header.Get("model-id")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	t.Cleanup(srv.Close)
	SetEndpoints(endpointOverride{SnapEngine: srv.URL})
	SetHTTPClient(srv.Client())

	cred := protocol.Credential{
		Type:            protocol.Provider,
		UserID:          "u1",
		AccessKeyID:     "AKIDchat",
		SecretAccessKey: "sk-chat",
		SecurityToken:   "sts-chat",
		ClientID:        protocol.ClientID,
	}
	protocol.SetAccountModels(protocol.AccountKey(cred), []protocol.ModelInfo{
		{ID: "glm-5.3-flash", Benefit: true},
	})
	storage, _ := protocol.MarshalCredential(cred)
	payload := []byte(`{"model":"glm-5.3-flash","messages":[{"role":"user","content":"hi"}]}`)
	req, _ := json.Marshal(map[string]any{
		"Model":       "glm-5.3-flash",
		"Payload":     payload,
		"StorageJSON": storage,
		"Stream":      false,
	})
	raw := mustResult(t, pluginabi.MethodExecutorExecute, req)
	var resp pluginapi.ExecutorResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp.Payload), `"chat.completion"`) {
		t.Fatalf("payload = %s", resp.Payload)
	}
	if !strings.HasPrefix(gotAuth, "SDK-HMAC-SHA256 Access=") {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotMaas != "benefit" || gotModelID != "glm-5.3-flash" {
		t.Fatalf("benefit headers maas=%q model-id=%q", gotMaas, gotModelID)
	}
	signed := protocol.ParseSignedHeaders(gotAuth)
	for _, h := range []string{"maas_type", "model-id", "model-name"} {
		if !strings.Contains(signed, h) {
			t.Fatalf("SignedHeaders %q missing %s", signed, h)
		}
	}
}

func TestExecutorUsesDiscoveredBenefitWhenUserIDEmpty(t *testing.T) {
	resetForTest(t)
	var gotMaas string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMaas = r.Header.Get("maas_type")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	t.Cleanup(srv.Close)
	SetEndpoints(endpointOverride{SnapEngine: srv.URL})
	SetHTTPClient(srv.Client())

	cred := protocol.Credential{
		Type:            protocol.Provider,
		AccessKeyID:     "AKIDempty",
		SecretAccessKey: "sk-chat",
		SecurityToken:   "sts-chat",
		ClientID:        protocol.ClientID,
	}
	protocol.SetAccountModels(protocol.AccountKey(cred), []protocol.ModelInfo{
		{ID: "DeepSeek-V4.1-Flash", Benefit: true},
		{ID: "GLM-5.2", Benefit: false},
	})
	storage, _ := protocol.MarshalCredential(cred)
	req, _ := json.Marshal(map[string]any{
		"Model":       "DeepSeek-V4.1-Flash",
		"Payload":     []byte(`{"model":"DeepSeek-V4.1-Flash","messages":[{"role":"user","content":"hi"}]}`),
		"StorageJSON": storage,
		"Stream":      false,
	})
	_ = mustResult(t, pluginabi.MethodExecutorExecute, req)
	if gotMaas != "benefit" {
		t.Fatalf("empty user_id should still send benefit headers, maas=%q", gotMaas)
	}
}

func TestExecutorRetriesWithBenefitOnRouteMissed(t *testing.T) {
	resetForTest(t)
	var hits int
	var secondMaas string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits == 1 {
			if r.Header.Get("maas_type") != "" {
				t.Fatal("first try should not send benefit headers")
			}
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error_code":"InferHub.002002009.404","error_msg":"The model is not registered, please request other model","details":[{"error_code":"InferHub.002002009.404","error_msg":"Route missed for model: GLM-5.3"}]}`))
			return
		}
		secondMaas = r.Header.Get("maas_type")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-retry","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"好"},"finish_reason":"stop"}]}`))
	}))
	t.Cleanup(srv.Close)
	SetEndpoints(endpointOverride{SnapEngine: srv.URL})
	SetHTTPClient(srv.Client())

	cred := protocol.Credential{
		Type:            protocol.Provider,
		AccessKeyID:     "AKIDretry",
		SecretAccessKey: "sk-chat",
		SecurityToken:   "sts-chat",
		ClientID:        protocol.ClientID,
	}
	storage, _ := protocol.MarshalCredential(cred)
	req, _ := json.Marshal(map[string]any{
		"Model":       "GLM-5.3",
		"Payload":     []byte(`{"model":"GLM-5.3","messages":[{"role":"user","content":"hi"}]}`),
		"StorageJSON": storage,
		"Stream":      false,
	})
	raw := mustResult(t, pluginabi.MethodExecutorExecute, req)
	var resp pluginapi.ExecutorResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Fatalf("hits = %d", hits)
	}
	if secondMaas != "benefit" {
		t.Fatalf("retry maas_type = %q", secondMaas)
	}
	if !strings.Contains(string(resp.Payload), "chatcmpl-retry") {
		t.Fatalf("payload = %s", resp.Payload)
	}
}

func TestModelRegisterAndStaticHaveNoOfflineCatalog(t *testing.T) {
	resetForTest(t)
	raw := mustResult(t, pluginabi.MethodModelRegister, nil)
	var reg pluginapi.ModelRegistrationResponse
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatal(err)
	}
	if reg.Provider != protocol.Provider {
		t.Fatalf("provider = %q", reg.Provider)
	}
	if len(reg.Models) != 0 {
		t.Fatalf("static register models = %+v", reg.Models)
	}
	staticRaw := mustResult(t, pluginabi.MethodModelStatic, nil)
	var static pluginapi.ModelResponse
	if err := json.Unmarshal(staticRaw, &static); err != nil {
		t.Fatal(err)
	}
	if len(static.Models) != 0 {
		t.Fatalf("static models = %+v", static.Models)
	}
	forAuth := mustResult(t, pluginabi.MethodModelForAuth, nil)
	var auth pluginapi.ModelResponse
	if err := json.Unmarshal(forAuth, &auth); err != nil {
		t.Fatal(err)
	}
	if len(auth.Models) != 0 {
		t.Fatalf("for_auth without cred models = %+v", auth.Models)
	}
	ident := resultMap(t, pluginabi.MethodAuthIdentifier, nil)
	if ident["identifier"] != protocol.Provider {
		t.Fatalf("auth identifier = %v", ident["identifier"])
	}
}

func TestManagementPasteSecretRedirectStaysPendingAndShowsContinueURL(t *testing.T) {
	resetForTest(t)
	tokenHits := 0
	ticketSecret := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/v1/login/ticket") {
			ticketSecret = r.URL.Query().Get("secret")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user_id":"","refresh_token":"","credentials":{}}`))
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/oauth2/tokens") {
			tokenHits++
			http.Error(w, "authorization_code must not run on first-hop secret", http.StatusBadRequest)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	SetEndpoints(endpointOverride{SnapManager: srv.URL, STSHost: srv.URL})
	SetHTTPClient(srv.Client())

	regReq, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("oauth_callback_port: 0\n")})
	_ = mustResult(t, pluginabi.MethodPluginRegister, regReq)
	startRaw := mustResult(t, pluginabi.MethodAuthLoginStart, nil)
	var start pluginapi.AuthLoginStartResponse
	if err := json.Unmarshal(startRaw, &start); err != nil {
		t.Fatal(err)
	}

	const pasted = "回调地址为：http://127.0.0.1/oauth/callback?secret=4246780b5c346fe0d0539f80545238652effd265af12fde05a06bd2e137a4f7e&redirect=https%3A%2F%2Fcodearts.huaweicloud.com%2Fportal%2Flogin%3Ftheme%3Dlight%26locale%3Dzh-cn%26authorizationAvailable%3Dfalse%26secret%3D4246780b5c346fe0d0539f80545238652effd265af12fde05a06bd2e137a4f7e"
	parts := applyPastedCallback(pasted)
	if parts.Code != "" {
		t.Fatalf("first hop parsed a code: %q", parts.Code)
	}
	if parts.Secret != "4246780b5c346fe0d0539f80545238652effd265af12fde05a06bd2e137a4f7e" {
		t.Fatalf("parsed secret = %q", parts.Secret)
	}
	if !strings.Contains(protocol.SafePortalRedirect(parts.Redirect), "codearts.huaweicloud.com/portal/login") {
		t.Fatalf("redirect = %q", parts.Redirect)
	}
	sess := latestSession()
	if sess == nil || sess.CapturedSecret != "4246780b5c346fe0d0539f80545238652effd265af12fde05a06bd2e137a4f7e" {
		t.Fatalf("captured secret = %+v", sess)
	}
	if sess.CapturedCode != "" {
		t.Fatalf("first hop captured a code: %q", sess.CapturedCode)
	}

	pollReq, _ := json.Marshal(map[string]any{"State": start.State})
	pollRaw := mustResult(t, pluginabi.MethodAuthLoginPoll, pollReq)
	var poll pluginapi.AuthLoginPollResponse
	if err := json.Unmarshal(pollRaw, &poll); err != nil {
		t.Fatal(err)
	}
	if poll.Status != pluginapi.AuthLoginStatusPending {
		t.Fatalf("poll status = %q message=%q", poll.Status, poll.Message)
	}
	if tokenHits != 0 {
		t.Fatalf("authorization_code exchange ran on secret-only callback, hits=%d", tokenHits)
	}
	if ticketSecret != "4246780b5c346fe0d0539f80545238652effd265af12fde05a06bd2e137a4f7e" {
		t.Fatalf("ticket poll secret = %q", ticketSecret)
	}
}

func TestOAuthCallbackHTTPFirstHopDoesNotRedirectOrFail(t *testing.T) {
	resetForTest(t)
	redirect := "https://codearts.huaweicloud.com/portal/login?theme=light&locale=zh-cn&authorizationAvailable=false&secret=abc"
	req := httptest.NewRequest(http.MethodGet, "/oauth/callback?secret=abc&redirect="+url.QueryEscape(redirect), nil)
	rec := httptest.NewRecorder()
	handleOAuthCallbackHTTP(rec, req)
	if rec.Code == http.StatusTemporaryRedirect || rec.Code == http.StatusFound || rec.Header().Get("Location") != "" {
		t.Fatalf("first hop redirected: status=%d location=%s", rec.Code, rec.Header().Get("Location"))
	}
	body := rec.Body.String()
	if strings.Contains(body, "登录失败") {
		t.Fatalf("callback page says login failed:\n%s", body)
	}
	if !strings.Contains(body, `target="_blank"`) {
		t.Fatalf("callback continue link must open a new tab:\n%s", body)
	}
	if !strings.Contains(body, "portal/login") {
		t.Fatalf("callback page missing continue URL:\n%s", body)
	}
	if strings.Contains(body, "已接收授权码") || strings.Contains(body, "已记在本地") || strings.Contains(body, "127.0.0.1") || strings.Contains(body, "/oauth/callback") {
		t.Fatalf("unbound first hop offers a callback URL:\n%s", body)
	}
	if !strings.Contains(body, "未绑定到进行中的登录") {
		t.Fatalf("unbound first hop body:\n%s", body)
	}

	empty := httptest.NewRecorder()
	handleOAuthCallbackHTTP(empty, httptest.NewRequest(http.MethodGet, "/oauth/callback", nil))
	emptyBody := empty.Body.String()
	if strings.Contains(emptyBody, "登录失败") {
		t.Fatalf("empty callback must not say login failed:\n%s", emptyBody)
	}
	if strings.Contains(emptyBody, "127.0.0.1") || strings.Contains(emptyBody, "/oauth/callback") || strings.Contains(emptyBody, "粘贴") {
		t.Fatalf("empty callback offers a paste URL:\n%s", emptyBody)
	}
}

func TestCallbackDiscardUnlessStateTicketOrSoleSession(t *testing.T) {
	resetForTest(t)
	regReq, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("oauth_callback_port: 0\n")})
	_ = mustResult(t, pluginabi.MethodPluginRegister, regReq)

	start := func() pluginapi.AuthLoginStartResponse {
		t.Helper()
		raw := mustResult(t, pluginabi.MethodAuthLoginStart, nil)
		var resp pluginapi.AuthLoginStartResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			t.Fatal(err)
		}
		if resp.State == "" {
			t.Fatal("missing login state")
		}
		return resp
	}
	snap := func(id string) (code, secret string) {
		t.Helper()
		sessMu.Lock()
		defer sessMu.Unlock()
		s := sessions[id]
		if s == nil {
			t.Fatalf("missing session %s", id)
		}
		return s.CapturedCode, s.CapturedSecret
	}
	ticketOf := func(id string) string {
		t.Helper()
		sessMu.Lock()
		defer sessMu.Unlock()
		s := sessions[id]
		if s == nil || s.TicketID == "" {
			t.Fatalf("missing ticket for %s", id)
		}
		return s.TicketID
	}
	portOf := func(id string) int {
		t.Helper()
		sessMu.Lock()
		defer sessMu.Unlock()
		s := sessions[id]
		if s == nil || s.Port <= 0 {
			t.Fatalf("missing port for %s", id)
		}
		return s.Port
	}
	clearSessions := func() {
		sessMu.Lock()
		sessions = map[string]*loginSession{}
		sessMu.Unlock()
	}

	older := start()
	restoreOlder := keepSession(t, older.State)
	newer := start()
	restoreOlder()
	if older.State == newer.State {
		t.Fatal("login states collided")
	}

	applyPastedCallback("http://127.0.0.1:18080/oauth/callback?code=loose-code&secret=portal-secret-unmatched")
	rec := httptest.NewRecorder()
	handleOAuthCallbackHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/callback?code=http-loose-code&secret=portal-secret-http", nil))
	unbound := rec.Body.String()
	if strings.Contains(unbound, "已接收授权码") || strings.Contains(unbound, "/oauth/callback?") || strings.Contains(unbound, older.State) || strings.Contains(unbound, newer.State) {
		t.Fatalf("unbound code callback offers a paste URL:\n%s", unbound)
	}
	if !strings.Contains(unbound, "未绑定到进行中的登录") {
		t.Fatalf("unbound code callback body:\n%s", unbound)
	}
	for _, id := range []string{older.State, newer.State} {
		code, secret := snap(id)
		if code != "" || secret != "" {
			t.Fatalf("session %s stored unbound callback code=%q secret=%q", id, code, secret)
		}
	}

	applyPastedCallback("http://127.0.0.1:18080/oauth/callback?code=older-code&state=" + url.QueryEscape(older.State))
	if code, secret := snap(older.State); code != "older-code" || secret != "" {
		t.Fatalf("older after state bind code=%q secret=%q", code, secret)
	}
	if code, secret := snap(newer.State); code != "" || secret != "" {
		t.Fatalf("newer stored state-bound callback code=%q secret=%q", code, secret)
	}

	olderTicket := ticketOf(older.State)
	q := url.Values{}
	q.Set("secret", "portal-secret-older")
	q.Set("ticket_id", olderTicket)
	handleOAuthCallbackHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/oauth/callback?"+q.Encode(), nil))
	if code, secret := snap(older.State); code != "older-code" || secret != "portal-secret-older" {
		t.Fatalf("older after ticket bind code=%q secret=%q", code, secret)
	}
	if code, secret := snap(newer.State); code != "" || secret != "" {
		t.Fatalf("newer stored ticket-bound callback code=%q secret=%q", code, secret)
	}

	q = url.Values{}
	q.Set("code", "different-code")
	q.Set("state", older.State)
	handleOAuthCallbackHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/oauth/callback?"+q.Encode(), nil))
	if code, secret := snap(older.State); code != "older-code" || secret != "portal-secret-older" {
		t.Fatalf("second code overwrote capture code=%q secret=%q", code, secret)
	}
	if code, secret := snap(newer.State); code != "" || secret != "" {
		t.Fatalf("overwrite callback touched newer code=%q secret=%q", code, secret)
	}

	q = url.Values{}
	q.Set("secret", "other-portal-secret")
	q.Set("ticket_id", olderTicket)
	handleOAuthCallbackHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/oauth/callback?"+q.Encode(), nil))
	if _, secret := snap(older.State); secret != "portal-secret-older" {
		t.Fatalf("second secret overwrote capture: %q", secret)
	}

	q = url.Values{}
	q.Set("code", "newer-via-ticket")
	q.Set("state", "not-a-session")
	q.Set("ticket_id", ticketOf(newer.State))
	recTicket := httptest.NewRecorder()
	handleOAuthCallbackHTTP(recTicket, httptest.NewRequest(http.MethodGet, "/oauth/callback?"+q.Encode(), nil))
	if code, secret := snap(newer.State); code != "newer-via-ticket" || secret != "" {
		t.Fatalf("newer after foreign state + own ticket code=%q secret=%q", code, secret)
	}
	if code, secret := snap(older.State); code != "older-code" || secret != "portal-secret-older" {
		t.Fatalf("older changed by newer ticket code=%q secret=%q", code, secret)
	}
	wantNewer := managementCallbackURL(portOf(newer.State), "newer-via-ticket", newer.State)
	if !strings.Contains(recTicket.Body.String(), html.EscapeString(wantNewer)) || strings.Contains(recTicket.Body.String(), "not-a-session") || strings.Contains(recTicket.Body.String(), older.State) {
		t.Fatalf("ticket-bound page:\n%s", recTicket.Body.String())
	}

	for _, raw := range []string{
		"/oauth/callback?code=unknown-state-code&state=missing-state",
		"/oauth/callback?code=unknown-ticket-code&ticket_id=missing-ticket",
	} {
		unknownRec := httptest.NewRecorder()
		handleOAuthCallbackHTTP(unknownRec, httptest.NewRequest(http.MethodGet, raw, nil))
		unknownBody := unknownRec.Body.String()
		if strings.Contains(unknownBody, "已接收授权码") || strings.Contains(unknownBody, "/oauth/callback?") || strings.Contains(unknownBody, older.State) || strings.Contains(unknownBody, newer.State) {
			t.Fatalf("unknown callback with two sessions:\n%s", unknownBody)
		}
		if !strings.Contains(unknownBody, "未绑定到进行中的登录") {
			t.Fatalf("unknown callback body:\n%s", unknownBody)
		}
	}
	if code, secret := snap(older.State); code != "older-code" || secret != "portal-secret-older" {
		t.Fatalf("unknown callback wrote older code=%q secret=%q", code, secret)
	}
	if code, secret := snap(newer.State); code != "newer-via-ticket" || secret != "" {
		t.Fatalf("unknown callback wrote newer code=%q secret=%q", code, secret)
	}

	clearSessions()
	bodyOlder := start()
	restoreBodyOlder := keepSession(t, bodyOlder.State)
	bodyNewer := start()
	restoreBodyOlder()
	body := url.Values{}
	body.Set("code", "body-code")
	body.Set("ticket_id", ticketOf(bodyOlder.State))
	req := httptest.NewRequest(http.MethodPost, "/oauth/callback?secret=from-query", strings.NewReader(body.Encode()))
	handleOAuthCallbackHTTP(httptest.NewRecorder(), req)
	if code, secret := snap(bodyOlder.State); code != "body-code" || secret != "from-query" {
		t.Fatalf("merged body callback code=%q secret=%q", code, secret)
	}
	if code, secret := snap(bodyNewer.State); code != "" || secret != "" {
		t.Fatalf("merged body callback touched newer code=%q secret=%q", code, secret)
	}

	clearSessions()
	only := start()
	sessMu.Lock()
	sessions[only.State].Port = 19091
	sessMu.Unlock()
	q = url.Values{}
	q.Set("code", "ab/cd")
	q.Set("state", "missing-state")
	onlyRec := httptest.NewRecorder()
	handleOAuthCallbackHTTP(onlyRec, httptest.NewRequest(http.MethodGet, "/oauth/callback?"+q.Encode(), nil))
	onlyBody := onlyRec.Body.String()
	wantOnly := managementCallbackURL(19091, "ab/cd", only.State)
	if !strings.Contains(onlyBody, html.EscapeString(wantOnly)) || strings.Contains(onlyBody, "missing-state") {
		t.Fatalf("sole unknown state page:\n%s", onlyBody)
	}
	pasted := pasteURLFromCallbackPage(t, onlyBody)
	parsed, err := url.Parse(pasted)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("code") != "ab/cd" || parsed.Query().Get("state") != only.State {
		t.Fatalf("CPA query code=%q state=%q", parsed.Query().Get("code"), parsed.Query().Get("state"))
	}
	if code, secret := snap(only.State); code != "ab/cd" || secret != "" {
		t.Fatalf("sole unknown state code=%q secret=%q", code, secret)
	}
	handleOAuthCallbackHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/oauth/callback?code=other-code&state=still-missing", nil))
	if code, _ := snap(only.State); code != "ab/cd" {
		t.Fatalf("second code overwrote sole capture: %q", code)
	}

	clearSessions()
	onlyTicket := start()
	ticketRec := httptest.NewRecorder()
	handleOAuthCallbackHTTP(ticketRec, httptest.NewRequest(http.MethodGet, "/oauth/callback?code=should-drop-ticket&ticket_id=missing-ticket", nil))
	wantTicket := managementCallbackURL(portOf(onlyTicket.State), "should-drop-ticket", onlyTicket.State)
	if !strings.Contains(ticketRec.Body.String(), html.EscapeString(wantTicket)) || strings.Contains(ticketRec.Body.String(), "missing-ticket") {
		t.Fatalf("sole unknown ticket page:\n%s", ticketRec.Body.String())
	}
	if code, secret := snap(onlyTicket.State); code != "should-drop-ticket" || secret != "" {
		t.Fatalf("sole unknown ticket code=%q secret=%q", code, secret)
	}

	clearSessions()
	onlyBare := start()
	applyPastedCallback("http://127.0.0.1:18080/oauth/callback?code=sole-code")
	if code, _ := snap(onlyBare.State); code != "sole-code" {
		t.Fatalf("sole session did not bind code: %q", code)
	}
}

func TestLoginStartReplacesPreviousSession(t *testing.T) {
	resetForTest(t)
	regReq, _ := json.Marshal(lifecycleRequest{ConfigYAML: []byte("oauth_callback_port: 0\n")})
	_ = mustResult(t, pluginabi.MethodPluginRegister, regReq)

	firstRaw := mustResult(t, pluginabi.MethodAuthLoginStart, nil)
	var first pluginapi.AuthLoginStartResponse
	if err := json.Unmarshal(firstRaw, &first); err != nil {
		t.Fatal(err)
	}
	secondRaw := mustResult(t, pluginabi.MethodAuthLoginStart, nil)
	var second pluginapi.AuthLoginStartResponse
	if err := json.Unmarshal(secondRaw, &second); err != nil {
		t.Fatal(err)
	}
	sessMu.Lock()
	_, firstAlive := sessions[first.State]
	_, secondAlive := sessions[second.State]
	n := len(sessions)
	port := 0
	if sessions[second.State] != nil {
		port = sessions[second.State].Port
	}
	sessMu.Unlock()
	if firstAlive || !secondAlive || n != 1 || first.State == second.State {
		t.Fatalf("sessions=%d firstAlive=%v secondAlive=%v", n, firstAlive, secondAlive)
	}

	const huaweiState = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const huaweiCode = "sample-auth-code"
	q := url.Values{}
	q.Set("code", huaweiCode)
	q.Set("state", huaweiState)
	rec := httptest.NewRecorder()
	handleOAuthCallbackHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/callback?"+q.Encode(), nil))
	body := rec.Body.String()
	if strings.Contains(body, "未绑定到进行中的登录") || strings.Contains(body, huaweiState) {
		t.Fatalf("callback page:\n%s", body)
	}
	want := managementCallbackURL(port, huaweiCode, second.State)
	if !strings.Contains(body, html.EscapeString(want)) {
		t.Fatalf("page missing %s\n%s", want, body)
	}
	parsed, err := url.Parse(pasteURLFromCallbackPage(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Get("state") != second.State || parsed.Query().Get("code") != huaweiCode {
		t.Fatalf("CPA query code=%q state=%q", parsed.Query().Get("code"), parsed.Query().Get("state"))
	}
	sessMu.Lock()
	got := ""
	if sessions[second.State] != nil {
		got = sessions[second.State].CapturedCode
	}
	sessMu.Unlock()
	if got != huaweiCode {
		t.Fatalf("captured %q", got)
	}
}

func pasteURLFromCallbackPage(t *testing.T, body string) string {
	t.Helper()
	const marker = "http://127.0.0.1:"
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("callback page has no paste URL:\n%s", body)
	}
	rest := body[i:]
	j := strings.Index(rest, "<")
	if j < 0 {
		t.Fatalf("callback page URL is not closed:\n%s", body)
	}
	return html.UnescapeString(rest[:j])
}

func TestManagementRegisterExposesCallbackPageAndAuthenticatedPost(t *testing.T) {
	resetForTest(t)
	raw := mustResult(t, pluginabi.MethodManagementRegister, nil)
	var reg managementRegistrationJSON
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatal(err)
	}
	if len(reg.Resources) != 1 {
		t.Fatalf("resources = %+v", reg.Resources)
	}
	page := reg.Resources[0]
	if page.Menu != managementMenuName || page.Path != resourceCallbackRoute || page.Description == "" {
		t.Fatalf("resource = %+v", page)
	}
	if len(reg.Routes) != 3 {
		t.Fatalf("routes = %+v", reg.Routes)
	}
	got := map[string]managementRouteJSON{}
	for _, route := range reg.Routes {
		got[route.Path] = route
		if route.Method != http.MethodPost || route.Menu != "" || route.Description == "" {
			t.Fatalf("route = %+v", route)
		}
	}
	for _, path := range []string{managementLoginRoute, managementCallbackRoute, managementStatusRoute} {
		if _, ok := got[path]; !ok {
			t.Fatalf("missing %s in %+v", path, reg.Routes)
		}
	}
	status, result, _ := callManagement(t, pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/oauth"})
	if status != http.StatusNotFound || result.Message == "" {
		t.Fatalf("unrelated path status=%d result=%+v", status, result)
	}
}
