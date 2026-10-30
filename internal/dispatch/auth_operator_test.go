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

func TestRefreshSchedule(t *testing.T) {
	now := time.Date(2026, 10, 29, 13, 7, 31, 658100796, time.UTC)
	issued := now
	exp := time.Date(2026, 10, 29, 15, 7, 31, 601000000, time.UTC)
	const half = 3599 * time.Second

	t.Run("two hour token waits until half life", func(t *testing.T) {
		at, secs := refreshSchedule(now, exp.Format(time.RFC3339Nano), issued)
		if secs != int(half/time.Second) || !at.Equal(exp.Add(-half)) {
			t.Fatalf("at=%s secs=%d", at.Format(time.RFC3339Nano), secs)
		}
	})
	t.Run("inside the second half waits two minutes", func(t *testing.T) {
		at, secs := refreshSchedule(exp.Add(-30*time.Minute), exp.Format(time.RFC3339Nano), issued)
		want := exp.Add(-30 * time.Minute).Add(refreshRetryFloor)
		if secs != int(half/time.Second) || !at.Equal(want) {
			t.Fatalf("at=%s secs=%d", at.Format(time.RFC3339Nano), secs)
		}
	})
	t.Run("expired waits two minutes and keeps the half-life interval", func(t *testing.T) {
		later := exp.Add(time.Hour)
		at, secs := refreshSchedule(later, exp.Format(time.RFC3339Nano), issued)
		if secs != int(half/time.Second) || !at.Equal(later.Add(refreshRetryFloor)) {
			t.Fatalf("at=%s secs=%d", at.Format(time.RFC3339Nano), secs)
		}
	})
	t.Run("unknown lifetime does not refresh", func(t *testing.T) {
		for _, tc := range []struct {
			expiration string
			issued     time.Time
		}{
			{expiration: "not-a-timestamp", issued: issued},
			{expiration: exp.Format(time.RFC3339Nano), issued: time.Time{}},
			{expiration: issued.Format(time.RFC3339Nano), issued: exp},
			{expiration: issued.Add(time.Second).Format(time.RFC3339Nano), issued: issued},
		} {
			at, secs := refreshSchedule(now, tc.expiration, tc.issued)
			if !at.IsZero() || secs != 0 {
				t.Fatalf("expiration=%q at=%s secs=%d", tc.expiration, at.Format(time.RFC3339Nano), secs)
			}
		}
	})
}

func TestFinishLoginKeepsOperatorFields(t *testing.T) {
	resetForTest(t)

	const kept = `{"type":"codearts","user_id":"u-keep","access_key_id":"AKOLD","secret_access_key":"old","security_token":"old","refresh_token":"rt-old","prefix":"codearts","disabled":true,"priority":7,"proxy_url":"http://proxy.example","note":"prod","next_refresh_after":"2000-01-01T00:00:00Z"}`
	const other = `{"type":"codearts","prefix":"other","disabled":true,"priority":9}`
	host := &operatorHost{
		files: map[string]operatorFile{
			"idx-keep":  {name: "codearts-u-keep.json", raw: []byte(kept)},
			"idx-other": {name: "codearts-other.json", raw: []byte(other)},
		},
	}
	SetCaller(host)
	dpop, err := protocol.NewDPoPPrivateJWK()
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	auth, hard := finishLogin(&loginSession{
		ID:       "sess-keep",
		Verifier: "verifier",
		DPoP:     dpop,
	}, protocol.TokenResponse{
		UserID:       "u-keep",
		UserName:     "keep",
		RefreshToken: "rt-new",
		Credentials: protocol.STSCreds{
			AccessKeyID:     "AKNEW",
			SecretAccessKey: "sk-new",
			SecurityToken:   "st-new",
			Expiration:      exp,
		},
	}, "cb")
	if hard != nil {
		t.Fatal(hard.Msg)
	}
	if auth.Prefix != "codearts" || !auth.Disabled || auth.ProxyURL != "http://proxy.example" {
		t.Fatalf("auth prefix=%q disabled=%t proxy=%q", auth.Prefix, auth.Disabled, auth.ProxyURL)
	}
	if auth.Metadata["disabled"] != true {
		t.Fatalf("metadata disabled = %#v", auth.Metadata["disabled"])
	}
	saved := string(host.saved)
	for _, key := range []string{`"prefix":"codearts"`, `"disabled":true`, `"priority":7`, `"note":"prod"`, `"proxy_url":"http://proxy.example"`, `"refresh_token":"rt-new"`, `"access_key_id":"AKNEW"`} {
		if !strings.Contains(saved, key) {
			t.Fatalf("saved file missing %s: %s", key, saved)
		}
	}
	if strings.Contains(saved, `"prefix":"other"`) || strings.Contains(saved, `"priority":9`) || strings.Contains(saved, "2000-01-01") {
		t.Fatalf("saved file kept another account or a past schedule: %s", saved)
	}
	stored := storedStringField(host.saved, "next_refresh_after")
	at, ok := parseRFC3339(stored)
	if !ok || at.Before(time.Now().Add(11*time.Hour+50*time.Minute)) || at.After(time.Now().Add(12*time.Hour+10*time.Minute)) {
		t.Fatalf("next_refresh_after = %q", stored)
	}
	secs, ok := intervalSeconds(auth.Metadata["refresh_interval_seconds"])
	if !ok || secs < 11*60*60+50*60 || secs > 12*60*60 {
		t.Fatalf("refresh_interval_seconds = %#v", auth.Metadata["refresh_interval_seconds"])
	}
}

func TestRefreshKeepsOperatorFields(t *testing.T) {
	resetForTest(t)
	dpop, err := protocol.NewDPoPPrivateJWK()
	if err != nil {
		t.Fatal(err)
	}
	prev := protocol.Credential{
		Type:            protocol.Provider,
		UserID:          "u-keep",
		AccessKeyID:     "AKOLD",
		SecretAccessKey: "skold",
		SecurityToken:   "sts-old",
		RefreshToken:    "rt-old",
		CodeVerifier:    "verifier-1",
		ClientID:        protocol.ClientID,
		DPoPPrivateKey:  map[string]string{"kty": dpop["kty"], "crv": dpop["crv"], "x": dpop["x"], "y": dpop["y"], "d": dpop["d"]},
	}
	own, err := protocol.MarshalCredential(prev)
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]any
	if err := json.Unmarshal(own, &file); err != nil {
		t.Fatal(err)
	}
	file["prefix"] = "codearts"
	file["disabled"] = true
	file["priority"] = 7
	file["note"] = "prod"
	storage, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/v1/oauth2/tokens") {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "rt-old" {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"user_id":"u-keep","refresh_token":"rt-new","credentials":{"access_key_id":"AKNEW","secret_access_key":"sknew","security_token":"sts-new","expiration":%q}}`, exp)
	}))
	t.Cleanup(srv.Close)
	SetEndpoints(endpointOverride{STSHost: srv.URL})
	SetHTTPClient(srv.Client())
	req, _ := json.Marshal(map[string]any{
		"StorageJSON": storage,
		"FileName":    "codearts-u-keep.json",
	})
	raw := mustResult(t, pluginabi.MethodAuthRefresh, req)
	var resp pluginapi.AuthRefreshResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Auth.Prefix != "codearts" || !resp.Auth.Disabled {
		t.Fatalf("prefix=%q disabled=%t", resp.Auth.Prefix, resp.Auth.Disabled)
	}
	body := string(resp.Auth.StorageJSON)
	for _, key := range []string{`"prefix":"codearts"`, `"disabled":true`, `"priority":7`, `"note":"prod"`, `"refresh_token":"rt-new"`} {
		if !strings.Contains(body, key) {
			t.Fatalf("refresh storage missing %s: %s", key, body)
		}
	}
	if !strings.Contains(body, `"next_refresh_after":"`) {
		t.Fatalf("refresh storage missing schedule: %s", body)
	}
}

type operatorFile struct {
	name string
	raw  []byte
}

type operatorHost struct {
	files map[string]operatorFile
	saved []byte
}

func (h *operatorHost) Call(method string, payload []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodHostAuthList:
		files := make([]map[string]any, 0, len(h.files))
		for index, file := range h.files {
			files = append(files, map[string]any{
				"name":       file.name,
				"auth_index": index,
				"path":       "/auth/" + file.name,
			})
		}
		return hostResult(map[string]any{"files": files})
	case pluginabi.MethodHostAuthGet:
		var req struct {
			AuthIndex string `json:"auth_index"`
		}
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, err
		}
		file := h.files[req.AuthIndex]
		return hostResult(map[string]any{"auth_index": req.AuthIndex, "name": file.name, "json": json.RawMessage(file.raw)})
	case pluginabi.MethodHostAuthSave:
		var req pluginapi.HostAuthSaveRequest
		if err := json.Unmarshal(payload, &req); err != nil {
			return nil, err
		}
		h.saved = append([]byte(nil), req.JSON...)
		return hostResult(map[string]any{"name": req.Name})
	default:
		return hostResult(map[string]any{})
	}
}

func hostResult(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}
