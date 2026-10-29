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
	"time"

	"github.com/dddwill8/codeartsPlugin/internal/protocol"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestAuthRefreshSchedule(t *testing.T) {
	const fractional = "2026-10-27T15:06:45.78Z"
	t.Run("fractional RFC3339", func(t *testing.T) {
		before := time.Now().UTC()
		got := authRefreshNext(t, fractional)
		assertScheduledRefresh(t, before, got, fractional)
		t.Logf("NextRefreshAfter fractional=%s", got.UTC().Format(time.RFC3339Nano))
	})

	t.Run("unparseable", func(t *testing.T) {
		before := time.Now().UTC()
		got := authRefreshNext(t, "not-a-timestamp").UTC()
		assertScheduledRefresh(t, before, got, "not-a-timestamp")
		t.Logf("NextRefreshAfter unparseable=%s", got.Format(time.RFC3339Nano))
	})
}

func authRefreshNext(t *testing.T, expiration string) time.Time {
	t.Helper()
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
		_, _ = io.WriteString(w, fmt.Sprintf(`{"user_id":"u-refresh","refresh_token":"rt-new","credentials":{"access_key_id":"AKNEW","secret_access_key":"sknew","security_token":"sts-new","expiration":%q}}`, expiration))
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
	if next.Expiration != expiration || next.RefreshToken != "rt-new" {
		t.Fatalf("refresh not applied: expiration=%q refresh_token=%q", next.Expiration, next.RefreshToken)
	}
	return resp.NextRefreshAfter
}
