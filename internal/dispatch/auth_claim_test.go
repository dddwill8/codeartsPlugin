package dispatch

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// TestPollClaimsCodeOnce checks that two overlapping polls exchange one
// captured authorization code a single time.
func TestPollClaimsCodeOnce(t *testing.T) {
	resetForTest(t)
	var tokenHits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/oauth2/tokens") {
			tokenHits.Add(1)
			http.Error(w, "reject code exchange", http.StatusBadRequest)
			return
		}
		if strings.Contains(r.URL.Path, "/v1/login/ticket") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user_id":"","refresh_token":"","credentials":{}}`))
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
	if start.State == "" {
		t.Fatal("missing login state")
	}
	captureCallback("claimed-once", "", start.State, "")
	pollReq, _ := json.Marshal(map[string]any{"State": start.State})

	var ready sync.WaitGroup
	ready.Add(2)
	var goStart sync.WaitGroup
	goStart.Add(1)
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			ready.Done()
			goStart.Wait()
			_, err := Handle(pluginabi.MethodAuthLoginPoll, pollReq)
			errCh <- err
		}()
	}
	ready.Wait()
	goStart.Done()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := tokenHits.Load(); got != 1 {
		t.Fatalf("token endpoint hits = %d, want 1", got)
	}
}

// TestPollFailureKeepsCodeArrivedDuringExchange checks that a code stored
// while exchange is in flight survives a rejected exchange.
func TestPollFailureKeepsCodeArrivedDuringExchange(t *testing.T) {
	resetForTest(t)
	arrived := make(chan struct{})
	release := make(chan struct{})
	var signal sync.Once
	var releaseOnce sync.Once
	unlock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unlock)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/oauth2/tokens") {
			signal.Do(func() { close(arrived) })
			<-release
			http.Error(w, "reject code exchange", http.StatusBadRequest)
			return
		}
		if strings.Contains(r.URL.Path, "/v1/login/ticket") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user_id":"","refresh_token":"","credentials":{}}`))
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
	if start.State == "" {
		t.Fatal("missing login state")
	}
	const original = "original-code"
	const newer = "newer-code"
	captureCallback(original, "", start.State, "")
	pollReq, _ := json.Marshal(map[string]any{"State": start.State})

	type pollResult struct {
		err error
	}
	done := make(chan pollResult, 1)
	go func() {
		_, err := Handle(pluginabi.MethodAuthLoginPoll, pollReq)
		done <- pollResult{err: err}
	}()

	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("token request did not arrive")
	}
	captureCallback(newer, "", start.State, "")
	unlock()

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatal(res.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("poll did not return")
	}

	sessMu.Lock()
	sess := sessions[start.State]
	got := ""
	if sess != nil {
		got = sess.CapturedCode
	}
	sessMu.Unlock()
	if sess == nil {
		t.Fatal("login session was deleted after a rejected exchange")
	}
	if got != newer {
		t.Fatalf("CapturedCode = %q, want %q", got, newer)
	}
}
