package dispatch

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// TestLoginPollCallbackRace overlaps auth.login.poll with captureCallback.
// Rejecting code exchange keeps the session in flight so both captured fields
// stay on the poll path. The test passes when those accesses do not race.
func TestLoginPollCallbackRace(t *testing.T) {
	resetForTest(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/v1/login/ticket") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"user_id":"","refresh_token":"","credentials":{}}`))
			return
		}
		http.Error(w, "reject code exchange", http.StatusBadRequest)
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
	pollReq, _ := json.Marshal(map[string]any{"State": start.State})

	const polls = 400
	var polling atomic.Bool
	polling.Store(true)
	var captures atomic.Int64
	var ready sync.WaitGroup
	ready.Add(2)
	var goStart sync.WaitGroup
	goStart.Add(1)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ready.Done()
		goStart.Wait()
		for i := 0; polling.Load(); i++ {
			if i%2 == 0 {
				captureCallback("race-code-a", "race-secret-a", start.State, "")
			} else {
				captureCallback("race-code-b", "race-secret-b", start.State, "")
			}
			captures.Add(1)
		}
	}()
	go func() {
		defer wg.Done()
		ready.Done()
		goStart.Wait()
		for i := 0; i < polls; i++ {
			_, _ = Handle(pluginabi.MethodAuthLoginPoll, pollReq)
		}
		polling.Store(false)
	}()
	ready.Wait()
	goStart.Done()
	wg.Wait()
	if captures.Load() == 0 {
		t.Fatal("captureCallback did not run alongside poll")
	}
}
