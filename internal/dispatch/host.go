package dispatch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// Caller is the CPA host RPC (host.http.do, host.auth.save, host.stream.emit, ...).
type Caller interface {
	Call(method string, payload []byte) ([]byte, error)
}

var (
	callerMu sync.RWMutex
	caller   Caller

	httpMu     sync.RWMutex
	httpClient = &http.Client{Timeout: 45 * time.Second}
)

// SetCaller installs the C ABI host callback.
func SetCaller(c Caller) {
	callerMu.Lock()
	caller = c
	callerMu.Unlock()
}

func currentCaller() Caller {
	callerMu.RLock()
	defer callerMu.RUnlock()
	return caller
}

// SetHTTPClient replaces the fallback net/http client (tests).
func SetHTTPClient(c *http.Client) {
	httpMu.Lock()
	defer httpMu.Unlock()
	if c == nil {
		httpClient = &http.Client{Timeout: 45 * time.Second}
		return
	}
	httpClient = c
}

func currentHTTP() *http.Client {
	httpMu.RLock()
	defer httpMu.RUnlock()
	return httpClient
}

func callHost(method string, payload any) (json.RawMessage, error) {
	return callCaller(currentCaller(), method, payload)
}

// callCaller invokes c, not whatever currentCaller is now.
// The caller lock is not held across Call; Call can block while SetCaller runs.
func callCaller(c Caller, method string, payload any) (json.RawMessage, error) {
	if c == nil {
		return nil, fmt.Errorf("host callback is unavailable")
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	resp, err := c.Call(method, raw)
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(resp, &env); err != nil {
		return nil, fmt.Errorf("decode host envelope: %w", err)
	}
	if !env.OK {
		if env.Error != nil {
			return nil, fmt.Errorf("%s: %s", env.Error.Code, env.Error.Message)
		}
		return nil, fmt.Errorf("host callback %s failed", method)
	}
	return env.Result, nil
}

func readRequestBody(req *http.Request) []byte {
	if req == nil || req.Body == nil {
		return nil
	}
	body, _ := io.ReadAll(req.Body)
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	return body
}

func hostHTTPDo(callbackID string, req *http.Request) (*http.Response, error) {
	body := readRequestBody(req)
	c := currentCaller()
	if c == nil || callbackID == "" {
		return currentHTTP().Do(req)
	}
	payload := map[string]any{
		"method":           req.Method,
		"url":              req.URL.String(),
		"headers":          req.Header,
		"body":             body,
		"host_callback_id": callbackID,
	}
	result, err := callHost(pluginabi.MethodHostHTTPDo, payload)
	if err != nil {
		return nil, err
	}
	var resp struct {
		StatusCode int         `json:"StatusCode"`
		Headers    http.Header `json:"Headers"`
		Body       []byte      `json:"Body"`
		AltStatus  int         `json:"status_code"`
		AltHeaders http.Header `json:"headers"`
		AltBody    []byte      `json:"body"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, err
	}
	status := resp.StatusCode
	if status == 0 {
		status = resp.AltStatus
	}
	if status == 0 {
		status = http.StatusOK
	}
	hdr := resp.Headers
	if len(hdr) == 0 {
		hdr = resp.AltHeaders
	}
	raw := resp.Body
	if len(raw) == 0 {
		raw = resp.AltBody
	}
	out := &http.Response{
		StatusCode: status,
		Header:     hdr,
		Body:       io.NopCloser(bytes.NewReader(raw)),
		Request:    req,
	}
	return out, nil
}

func hostAuthSave(name string, rawJSON []byte) error {
	if currentCaller() == nil {
		return nil
	}
	_, err := callHost(pluginabi.MethodHostAuthSave, pluginapi.HostAuthSaveRequest{
		Name: name,
		JSON: rawJSON,
	})
	return err
}

func hostStreamEmit(streamID string, payload []byte) error {
	return hostStreamEmitOn(currentCaller(), streamID, payload)
}

func hostStreamEmitOn(c Caller, streamID string, payload []byte) error {
	if strings.TrimSpace(streamID) == "" || c == nil {
		return nil
	}
	_, err := callCaller(c, pluginabi.MethodHostStreamEmit, map[string]any{
		"stream_id": streamID,
		"payload":   payload,
	})
	return err
}

func hostStreamClose(streamID, errMsg string) {
	hostStreamCloseOn(currentCaller(), streamID, errMsg)
}

func hostStreamCloseOn(c Caller, streamID, errMsg string) {
	hostStreamCloseStatus(c, streamID, errMsg, 0)
}

// hostStreamCloseStatus closes a plugin stream. A positive status is sent as
// error_detail so CPA can tell a client parameter error from an auth failure.
func hostStreamCloseStatus(c Caller, streamID, errMsg string, status int) {
	if strings.TrimSpace(streamID) == "" || c == nil {
		return
	}
	payload := map[string]any{"stream_id": streamID}
	if errMsg != "" {
		payload["error"] = errMsg
		if status > 0 {
			payload["error_detail"] = map[string]any{
				"code":        "upstream_error",
				"message":     errMsg,
				"http_status": status,
			}
		}
	}
	_, _ = callCaller(c, pluginabi.MethodHostStreamClose, payload)
}

func hostHTTPDoStream(callbackID string, req *http.Request) (status int, headers http.Header, streamID string, body []byte, err error) {
	rawBody := readRequestBody(req)
	c := currentCaller()
	if c == nil || callbackID == "" {
		req.Body = io.NopCloser(bytes.NewReader(rawBody))
		resp, errDo := currentHTTP().Do(req)
		if errDo != nil {
			return 0, nil, "", nil, errDo
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Clone(), "", b, nil
	}
	result, err := callHost(pluginabi.MethodHostHTTPDoStream, map[string]any{
		"method":           req.Method,
		"url":              req.URL.String(),
		"headers":          req.Header,
		"body":             rawBody,
		"host_callback_id": callbackID,
	})
	if err != nil {
		return 0, nil, "", nil, err
	}
	var resp struct {
		StatusCode int         `json:"status_code"`
		Headers    http.Header `json:"headers"`
		StreamID   string      `json:"stream_id"`
		Chunks     []struct {
			Payload []byte `json:"Payload"`
		} `json:"chunks"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return 0, nil, "", nil, err
	}
	var buf bytes.Buffer
	for _, ch := range resp.Chunks {
		buf.Write(ch.Payload)
	}
	return resp.StatusCode, resp.Headers, resp.StreamID, buf.Bytes(), nil
}

func hostHTTPStreamRead(streamID string) (payload []byte, done bool, err error) {
	return hostHTTPStreamReadOn(currentCaller(), streamID)
}

func hostHTTPStreamReadOn(c Caller, streamID string) (payload []byte, done bool, err error) {
	result, err := callCaller(c, pluginabi.MethodHostHTTPStreamRead, map[string]any{"stream_id": streamID})
	if err != nil {
		return nil, true, err
	}
	var resp struct {
		Payload []byte `json:"payload"`
		Error   string `json:"error"`
		Done    bool   `json:"done"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, true, err
	}
	if resp.Error != "" {
		return resp.Payload, true, fmt.Errorf("%s", resp.Error)
	}
	return resp.Payload, resp.Done, nil
}

func hostHTTPStreamClose(streamID string) {
	hostHTTPStreamCloseOn(currentCaller(), streamID)
}

func hostHTTPStreamCloseOn(c Caller, streamID string) {
	if streamID == "" || c == nil {
		return
	}
	_, _ = callCaller(c, pluginabi.MethodHostHTTPStreamClose, map[string]any{"stream_id": streamID})
}

func hostLog(level, msg string) {
	c := currentCaller()
	if c == nil {
		return
	}
	_, _ = callHost(pluginabi.MethodHostLog, map[string]any{"level": level, "message": msg})
}
