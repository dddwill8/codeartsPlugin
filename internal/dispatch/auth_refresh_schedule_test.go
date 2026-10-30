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
	t.Run("fractional RFC3339", func(t *testing.T) {
		before := time.Now().UTC()
		expiration := before.Add(2 * time.Hour).Format(time.RFC3339Nano)
		got, meta := authRefreshNext(t, expiration)
		assertAuthSchedule(t, before, got, meta)
	})

	t.Run("unparseable", func(t *testing.T) {
		got, meta := authRefreshNext(t, "not-a-timestamp")
		secs, _ := intervalSeconds(meta["refresh_interval_seconds"])
		if secs != 0 || !got.IsZero() {
			t.Fatalf("NextRefreshAfter %s interval %#v", got.Format(time.RFC3339Nano), meta["refresh_interval_seconds"])
		}
	})
}

func authRefreshNext(t *testing.T, expiration string) (time.Time, map[string]any) {
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
	return resp.NextRefreshAfter, resp.Auth.Metadata
}

func TestSTSRefreshDoesNotReportUnauthorized(t *testing.T) {
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
	storage, err := protocol.MarshalCredential(prev)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := json.Marshal(map[string]any{
		"StorageJSON": storage,
		"FileName":    "codearts-u-refresh.json",
	})

	t.Run("missing material is not 401", func(t *testing.T) {
		broken := prev
		broken.DPoPPrivateKey = map[string]string{"kty": "EC"}
		raw, err := protocol.MarshalCredential(broken)
		if err != nil {
			t.Fatal(err)
		}
		bad, _ := json.Marshal(map[string]any{"StorageJSON": raw, "FileName": "codearts-u-refresh.json"})
		env := mustHandle(t, pluginabi.MethodAuthRefresh, bad)
		if env.OK || env.Error == nil || env.Error.HTTPStatus != http.StatusBadGateway {
			t.Fatalf("status=%v message=%v", env.Error, env.Error)
		}
	})

	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   int
		code   string
	}{
		{name: "invalid grant stays 400", status: http.StatusBadRequest, body: `{"error":"invalid_grant","error_description":"rotated"}`, want: http.StatusBadRequest, code: "invalid_grant"},
		{name: "upstream 401 is retried", status: http.StatusUnauthorized, body: `{"error":"401 Unauthorized","error_description":"no"}`, want: http.StatusBadGateway, code: "unknown"},
		{name: "upstream 500 is retried", status: http.StatusInternalServerError, body: `{"error_code":"server_error"}`, want: http.StatusBadGateway, code: "server_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			t.Cleanup(srv.Close)
			SetEndpoints(endpointOverride{STSHost: srv.URL})
			SetHTTPClient(srv.Client())
			env := mustHandle(t, pluginabi.MethodAuthRefresh, req)
			if env.OK || env.Error == nil {
				t.Fatal("expected refresh error")
			}
			if env.Error.HTTPStatus != tc.want || !strings.Contains(env.Error.Message, "error="+tc.code) {
				t.Fatalf("status=%d message=%q", env.Error.HTTPStatus, env.Error.Message)
			}
			lower := strings.ToLower(env.Error.Message)
			if strings.Contains(lower, "status 401") || strings.Contains(lower, "401 unauthorized") {
				t.Fatalf("message looks terminal to CPA: %q", env.Error.Message)
			}
		})
	}
}
