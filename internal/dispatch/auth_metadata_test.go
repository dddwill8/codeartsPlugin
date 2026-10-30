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

func TestAuthMetadataParse(t *testing.T) {
	resetForTest(t)
	const expiration = "2026-10-27T15:06:45.78Z"
	const issued = "2026-10-27T13:06:45.78Z"
	rawJSON := []byte(`{"type":"codearts","access_key_id":"AKIDx","secret_access_key":"s","security_token":"t","refresh_token":"rt","expiration":"` + expiration + `","updated_at":"` + issued + `"}`)
	req, err := json.Marshal(pluginapi.AuthParseRequest{RawJSON: rawJSON})
	if err != nil {
		t.Fatal(err)
	}
	raw := mustResult(t, pluginabi.MethodAuthParse, req)
	var resp pluginapi.AuthParseResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Handled {
		t.Fatal("Handled = false")
	}
	assertAuthRefreshMeta(t, resp.Auth.Metadata, expiration, "rt")
	assertAuthSchedule(t, time.Now().UTC(), resp.Auth.NextRefreshAfter, resp.Auth.Metadata)
	if resp.Auth.Metadata["last_refresh"] != issued {
		t.Fatalf("last_refresh = %#v", resp.Auth.Metadata["last_refresh"])
	}
}

func TestAuthMetadataRefresh(t *testing.T) {
	resetForTest(t)
	expiration := time.Now().UTC().Add(2 * time.Hour).Format(time.RFC3339Nano)
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/v1/oauth2/tokens") {
			http.NotFound(w, r)
			return
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
	assertAuthRefreshMeta(t, resp.Auth.Metadata, expiration, "rt-new")
	assertAuthSchedule(t, time.Now().UTC(), resp.NextRefreshAfter, resp.Auth.Metadata)
	assertAuthSchedule(t, time.Now().UTC(), resp.Auth.NextRefreshAfter, resp.Auth.Metadata)
	if resp.NextRefreshAfter.UnixNano() != resp.Auth.NextRefreshAfter.UnixNano() {
		t.Fatalf("NextRefreshAfter mismatch response=%s auth=%s", resp.NextRefreshAfter.Format(time.RFC3339Nano), resp.Auth.NextRefreshAfter.Format(time.RFC3339Nano))
	}
}

func assertAuthRefreshMeta(t *testing.T, meta map[string]any, expiresAt, refreshToken string) {
	t.Helper()
	if meta["expires_at"] != expiresAt {
		t.Fatalf("expires_at = %#v, want %q", meta["expires_at"], expiresAt)
	}
	if meta["refresh_token"] != refreshToken {
		t.Fatalf("refresh_token = %#v, want %q", meta["refresh_token"], refreshToken)
	}
	if _, ok := intervalSeconds(meta["refresh_interval_seconds"]); !ok {
		t.Fatalf("refresh_interval_seconds = %#v", meta["refresh_interval_seconds"])
	}
	if meta["type"] != protocol.Provider {
		t.Fatalf("type = %#v", meta["type"])
	}
}

func intervalSeconds(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), n == float64(int(n))
	case int:
		return n, true
	case int64:
		return int(n), true
	case json.Number:
		f, err := n.Float64()
		return int(f), err == nil && f == float64(int(f))
	default:
		return 0, false
	}
}

func assertAuthSchedule(t *testing.T, now, got time.Time, meta map[string]any) {
	t.Helper()
	now = now.UTC()
	got = got.UTC()
	secs, ok := intervalSeconds(meta["refresh_interval_seconds"])
	if !ok {
		t.Fatalf("refresh_interval_seconds = %#v", meta["refresh_interval_seconds"])
	}
	exp, expOK := parseRFC3339(fmt.Sprint(meta["expires_at"]))
	issued, issOK := parseRFC3339(fmt.Sprint(meta["last_refresh"]))
	if !expOK || !issOK {
		if secs != 0 || !got.IsZero() {
			t.Fatalf("unschedulable interval=%d next=%s", secs, got.Format(time.RFC3339Nano))
		}
		return
	}
	interval, okLife := refreshInterval(exp, issued)
	if !okLife {
		if secs != 0 || !got.IsZero() {
			t.Fatalf("unschedulable interval=%d next=%s", secs, got.Format(time.RFC3339Nano))
		}
		return
	}
	if secs != int(interval/time.Second) {
		t.Fatalf("refresh_interval_seconds = %d, want %d", secs, int(interval/time.Second))
	}
	want := now.Add(refreshRetryFloor)
	if exp.After(now) && exp.Sub(now) > interval {
		want = exp.Add(-interval)
	}
	if got.Before(want.Add(-3*time.Second)) || got.After(want.Add(3*time.Second)) {
		t.Fatalf("NextRefreshAfter %s want about %s", got.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
}
