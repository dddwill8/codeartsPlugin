package dispatch

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/dddwill8/codeartsPlugin/internal/protocol"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	testBuiltinModelID = "builtin-model"
	testBenefitModelID = "benefit-model"
)

func TestModelForAuth(t *testing.T) {
	resetForTest(t)

	var directHits atomic.Int32
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directHits.Add(1)
		t.Fatalf("model discovery hit direct HTTP: %s %s", r.Method, r.URL.String())
	}))
	t.Cleanup(direct.Close)
	SetEndpoints(endpointOverride{SnapEngine: direct.URL, Benefit: direct.URL})
	SetHTTPClient(direct.Client())

	caller := &recordingHostCaller{}
	SetCaller(caller)

	storage, err := json.Marshal(map[string]string{
		"access_key_id":     "AKIDmodel",
		"secret_access_key": "secret-model",
	})
	if err != nil {
		t.Fatal(err)
	}
	withCallback, err := json.Marshal(map[string]any{
		"host_callback_id": "cb-models",
		"StorageJSON":      storage,
	})
	if err != nil {
		t.Fatal(err)
	}

	raw := mustResult(t, pluginabi.MethodModelForAuth, withCallback)
	if directHits.Load() != 0 {
		t.Fatalf("direct HTTP requests = %d", directHits.Load())
	}
	var sawCatalogGET, sawClaimPOST bool
	for _, call := range caller.snapshot() {
		if call.method != pluginabi.MethodHostHTTPDo {
			t.Fatalf("unexpected host method %s", call.method)
		}
		if call.httpMethod == http.MethodGet && (strings.Contains(call.url, protocol.EpModelBuiltin) || strings.Contains(call.url, protocol.EpBenefitConfig)) {
			sawCatalogGET = true
		}
		if call.httpMethod == http.MethodPost && strings.Contains(call.url, protocol.EpBenefitClaim) {
			sawClaimPOST = true
		}
	}
	if !sawCatalogGET || !sawClaimPOST {
		t.Fatalf("host urls = %+v", caller.snapshot())
	}
	assertModelIDs(t, raw, testBuiltinModelID, testBenefitModelID)

	var direct2Hits atomic.Int32
	direct2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		direct2Hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(catalogBody(r.URL.RequestURI()))
	}))
	t.Cleanup(direct2.Close)
	SetEndpoints(endpointOverride{SnapEngine: direct2.URL, Benefit: direct2.URL})
	SetHTTPClient(direct2.Client())

	before := len(caller.snapshot())
	withoutCallback, err := json.Marshal(map[string]any{
		"StorageJSON": storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw = mustResult(t, pluginabi.MethodModelForAuth, withoutCallback)
	after := caller.snapshot()
	if len(after) != before {
		t.Fatalf("MethodHostHTTPDo called without host_callback_id: %+v", after[before:])
	}
	if direct2Hits.Load() == 0 {
		t.Fatal("direct HTTP was not used when host_callback_id is absent")
	}
	assertModelIDs(t, raw, testBuiltinModelID, testBenefitModelID)
}

type recordedHostCall struct {
	method     string
	httpMethod string
	url        string
}

type recordingHostCaller struct {
	mu    sync.Mutex
	calls []recordedHostCall
}

func (c *recordingHostCaller) Call(method string, payload []byte) ([]byte, error) {
	rec := recordedHostCall{method: method}
	var body []byte
	if method == pluginabi.MethodHostHTTPDo {
		var p struct {
			Method string `json:"method"`
			URL    string `json:"url"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		rec.httpMethod = p.Method
		rec.url = p.URL
		body = catalogBody(p.URL)
	}
	c.mu.Lock()
	c.calls = append(c.calls, rec)
	c.mu.Unlock()

	result, err := json.Marshal(struct {
		StatusCode int    `json:"StatusCode"`
		Body       []byte `json:"Body"`
	}{StatusCode: http.StatusOK, Body: body})
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: result})
}

func (c *recordingHostCaller) snapshot() []recordedHostCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]recordedHostCall, len(c.calls))
	copy(out, c.calls)
	return out
}

func catalogBody(rawURL string) []byte {
	switch {
	case strings.Contains(rawURL, protocol.EpAgentList):
		return []byte(`{"agents":[]}`)
	case strings.Contains(rawURL, protocol.EpModelBuiltin):
		return []byte(`{"builtinModels":[{"model_id":"` + testBuiltinModelID + `"}]}`)
	case strings.Contains(rawURL, protocol.EpBenefitConfig):
		return []byte(`{"error_code":"0000","result":{"models":[{"model_id":"` + testBenefitModelID + `"}]}}`)
	case strings.Contains(rawURL, protocol.EpBenefitClaim):
		return []byte(`{}`)
	default:
		return []byte(`{}`)
	}
}

func assertModelIDs(t *testing.T, raw []byte, ids ...string) {
	t.Helper()
	var resp pluginapi.ModelResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, m := range resp.Models {
		got[m.ID] = true
	}
	for _, id := range ids {
		if !got[id] {
			t.Fatalf("models = %+v, missing %s", resp.Models, id)
		}
	}
}
