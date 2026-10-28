package dispatch

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dddwill8/codeartsPlugin/internal/protocol"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
)

// streamHost fakes the CPA host RPC used by execute_stream.
// do_stream returns status, headers, and a stream id with no chunks.
// The response body is only available from stream_read.
type streamHost struct {
	mu      sync.Mutex
	methods []string
	maas    []string
	readIDs []string
	body    []byte
	doCalls int
	decode  error
}

func (h *streamHost) Call(method string, payload []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.methods = append(h.methods, method)
	switch method {
	case pluginabi.MethodHostHTTPDoStream:
		h.doCalls++
		var req struct {
			Headers http.Header `json:"headers"`
		}
		if err := json.Unmarshal(payload, &req); err != nil {
			h.decode = err
		}
		maas := ""
		if req.Headers != nil {
			maas = req.Headers.Get("maas_type")
		}
		h.maas = append(h.maas, maas)
		status := http.StatusNotFound
		streamID := "hs1"
		if h.doCalls > 1 {
			status = http.StatusOK
			streamID = "hs2"
		}
		return okEnvelope(map[string]any{
			"status_code": status,
			"headers":     http.Header{"Content-Type": []string{"application/json"}},
			"stream_id":   streamID,
		})
	case pluginabi.MethodHostHTTPStreamRead:
		var req struct {
			StreamID string `json:"stream_id"`
		}
		if err := json.Unmarshal(payload, &req); err != nil {
			h.decode = err
		}
		h.readIDs = append(h.readIDs, req.StreamID)
		if req.StreamID == "hs1" && len(h.readIDs) == 1 {
			return okEnvelope(map[string]any{
				"payload": h.body,
				"done":    true,
			})
		}
		return okEnvelope(map[string]any{"done": true})
	default:
		return okEnvelope(map[string]any{})
	}
}

func (h *streamHost) snapshot() (methods, maas, readIDs []string, doCalls int, decode error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.methods...), append([]string(nil), h.maas...), append([]string(nil), h.readIDs...), h.doCalls, h.decode
}

func executeStreamRequest(t *testing.T) []byte {
	t.Helper()
	cred := protocol.Credential{
		Type:            protocol.Provider,
		AccessKeyID:     "AKIDstream",
		SecretAccessKey: "sk-stream",
		SecurityToken:   "sts-stream",
	}
	storage, err := protocol.MarshalCredential(cred)
	if err != nil {
		t.Fatal(err)
	}
	req, err := json.Marshal(map[string]any{
		"Model":            "GLM-5.3",
		"Payload":          []byte(`{"model":"GLM-5.3","messages":[{"role":"user","content":"hi"}]}`),
		"StorageJSON":      storage,
		"host_callback_id": "cb-1",
		"stream_id":        "ps-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestExecuteStreamRetriesBenefitWhenRouteMissIsOnlyOnStreamRead(t *testing.T) {
	resetForTest(t)
	host := &streamHost{body: []byte(`{"error_code":"InferHub.002002009.404","error_msg":"Route missed for model: GLM-5.3"}`)}
	SetCaller(host)

	env := mustHandle(t, pluginabi.MethodExecutorExecuteStream, executeStreamRequest(t))
	if !env.OK {
		msg := ""
		if env.Error != nil {
			msg = env.Error.Code + ": " + env.Error.Message
		}
		t.Fatalf("execute_stream not ok: %s", msg)
	}

	methods, maas, readIDs, doCalls, decodeErr := host.snapshot()
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if doCalls != 2 || len(maas) != 2 {
		t.Fatalf("do_stream calls = %d maas=%v methods=%v", doCalls, maas, methods)
	}
	readAt := -1
	secondDo := -1
	seenDo := 0
	for i, method := range methods {
		if method == pluginabi.MethodHostHTTPStreamRead && readAt < 0 {
			readAt = i
		}
		if method == pluginabi.MethodHostHTTPDoStream {
			seenDo++
			if seenDo == 2 {
				secondDo = i
			}
		}
	}
	if readAt < 0 || secondDo < 0 || readAt > secondDo {
		t.Fatalf("stream_read index %d is not before second do_stream %d: %v", readAt, secondDo, methods)
	}
	if len(readIDs) == 0 || readIDs[0] != "hs1" {
		t.Fatalf("first stream_read id = %v", readIDs)
	}
	if maas[0] != "" {
		t.Fatalf("first maas_type = %q", maas[0])
	}
	if maas[1] != "benefit" {
		t.Fatalf("second maas_type = %q", maas[1])
	}
}

func TestExecuteStreamDoesNotRetryWhenStreamReadIsNotRouteMiss(t *testing.T) {
	resetForTest(t)
	const body = `{"error_code":"Some.Other","error_msg":"temporary upstream failure"}`
	host := &streamHost{body: []byte(body)}
	SetCaller(host)

	env := mustHandle(t, pluginabi.MethodExecutorExecuteStream, executeStreamRequest(t))
	if env.OK || env.Error == nil {
		t.Fatal("non-route-miss 404 should be upstream_error")
	}
	if env.Error.Code != "upstream_error" {
		t.Fatalf("error = %+v", env.Error)
	}
	if !strings.Contains(env.Error.Message, "temporary upstream failure") {
		t.Fatalf("error message = %q", env.Error.Message)
	}

	methods, maas, readIDs, doCalls, decodeErr := host.snapshot()
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if doCalls != 1 {
		t.Fatalf("opened %d streams, want 1: %v", doCalls, methods)
	}
	if len(readIDs) == 0 || readIDs[0] != "hs1" {
		t.Fatalf("stream_read ids = %v methods=%v", readIDs, methods)
	}
	if len(maas) != 1 || maas[0] == "benefit" {
		t.Fatalf("maas = %v", maas)
	}
}

// openedStreamHost returns HTTP 200 and a stream id with no chunks.
// The first stream_read signals entered and blocks until release is closed.
// Later reads return immediately with done:false.
type openedStreamHost struct {
	mu      sync.Mutex
	reads   int
	entered chan struct{}
	release chan struct{}
}

func (h *openedStreamHost) Call(method string, payload []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodHostHTTPDoStream:
		return okEnvelope(map[string]any{
			"status_code": http.StatusOK,
			"stream_id":   "hs-open",
		})
	case pluginabi.MethodHostHTTPStreamRead:
		h.mu.Lock()
		h.reads++
		first := h.reads == 1
		h.mu.Unlock()
		if first {
			close(h.entered)
			<-h.release
		}
		return okEnvelope(map[string]any{"done": false})
	default:
		return okEnvelope(map[string]any{})
	}
}

func (h *openedStreamHost) streamReads() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.reads
}

// replacementCaller records every Call. A hit means the forwarder followed SetCaller.
type replacementCaller struct {
	mu      sync.Mutex
	methods []string
}

func (c *replacementCaller) Call(method string, payload []byte) ([]byte, error) {
	c.mu.Lock()
	c.methods = append(c.methods, method)
	c.mu.Unlock()
	return okEnvelope(map[string]any{})
}

func (c *replacementCaller) calls() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.methods))
	copy(out, c.methods)
	return out
}

func TestForwardHostStreamStopsWhenCallerIsReplaced(t *testing.T) {
	resetForTest(t)

	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	closeRelease := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(closeRelease)

	host := &openedStreamHost{entered: entered, release: release}
	SetCaller(host)

	env := mustHandle(t, pluginabi.MethodExecutorExecuteStream, executeStreamRequest(t))
	if !env.OK {
		msg := ""
		if env.Error != nil {
			msg = env.Error.Code + ": " + env.Error.Message
		}
		t.Fatalf("execute_stream not ok: %s", msg)
	}

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first stream_read")
	}

	repl := &replacementCaller{}
	SetCaller(repl)
	closeRelease()

	deadline := time.Now().Add(time.Second)
	last := -1
	stable := 0
	for time.Now().Before(deadline) {
		if calls := repl.calls(); len(calls) != 0 {
			t.Fatalf("replacement caller invoked: %v", calls)
		}
		reads := host.streamReads()
		if reads > 2 {
			t.Fatalf("stream_read count climbed to %d", reads)
		}
		if reads == last && (reads == 1 || reads == 2) {
			stable++
			if stable >= 5 {
				if calls := repl.calls(); len(calls) != 0 {
					t.Fatalf("replacement caller invoked: %v", calls)
				}
				return
			}
		} else {
			stable = 0
			last = reads
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("forwarder did not stop: stream_read=%d replacement=%v", host.streamReads(), repl.calls())
}
