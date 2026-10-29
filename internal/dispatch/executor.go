package dispatch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/dddwill8/codeartsPlugin/internal/protocol"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type rpcExecutorRequest struct {
	pluginapi.ExecutorRequest
	StreamID       string `json:"stream_id,omitempty"`
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

func handleExecute(request []byte, streamRPC bool) ([]byte, error) {
	var req rpcExecutorRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return errorEnvelope("invalid_request", err.Error(), http.StatusBadRequest), nil
	}
	if req.HostCallbackID == "" {
		req.HostCallbackID = jsonString(request, "host_callback_id")
	}
	if req.StreamID == "" {
		req.StreamID = jsonString(request, "stream_id")
	}
	raw := req.StorageJSON
	if len(raw) == 0 {
		raw = jsonBytes(request, "StorageJSON", "storage_json")
	}
	cred, err := protocol.ParseCredential(raw)
	if err != nil {
		return errorEnvelope("executor_error", err.Error(), http.StatusUnauthorized), nil
	}
	if cred.AccessKeyID == "" || cred.SecretAccessKey == "" {
		return errorEnvelope("executor_error", "missing STS access_key_id/secret_access_key", http.StatusUnauthorized), nil
	}
	model := req.Model
	if model == "" {
		model = jsonString(request, "Model", "model")
	}
	payload := req.Payload
	if len(payload) == 0 {
		payload = req.OriginalRequest
	}
	if len(payload) == 0 {
		payload = jsonBytes(request, "Payload", "payload", "OriginalRequest", "original_request")
	}
	stream := streamRPC || req.Stream || jsonBool(request, "Stream", "stream")
	payloadModel := jsonString(payload, "model")
	if model == "" {
		model = payloadModel
	}
	// Huawei only knows the bare id (GLM-5.3). CPA strips auth.Prefix from
	// req.Model before a built-in executor runs, but a plugin still receives the
	// client payload, so codearts/GLM-5.3 can remain in the body after req.Model
	// is already GLM-5.3. Strip both before the body, benefit lookup, and headers.
	prefix := authPrefix(req.AuthMetadata, req.AuthAttributes, raw)
	model = protocol.StripModelPrefix(model, prefix)
	payloadModel = protocol.StripModelPrefix(payloadModel, prefix)
	if payloadModel != "" {
		model = payloadModel
	}
	body, model, err := protocol.PrepareChatBody(payload, model, stream)
	if err != nil {
		return errorEnvelope("executor_error", err.Error(), http.StatusBadRequest), nil
	}
	benefit := protocol.IsBenefitModel(protocol.AccountKey(cred), model)
	target := protocol.ChatTarget(snapEngineBase())
	sign := protocol.SignCredentialFrom(cred)
	httpReq, err := protocol.NewChatRequest(target, body, sign, model, benefit, stream, protocol.SignOptions{})
	if err != nil {
		return errorEnvelope("executor_error", err.Error(), http.StatusInternalServerError), nil
	}

	if stream {
		return executeStream(req.HostCallbackID, req.StreamID, httpReq, func() (*http.Request, error) {
			if benefit {
				return nil, nil
			}
			return protocol.NewChatRequest(target, body, sign, model, true, true, protocol.SignOptions{})
		})
	}
	resp, err := hostHTTPDo(req.HostCallbackID, httpReq)
	if err != nil {
		return errorEnvelope("executor_error", err.Error(), http.StatusBadGateway), nil
	}
	rawResp, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound && !benefit && routeMissed(rawResp) {
		retryReq, retryErr := protocol.NewChatRequest(target, body, sign, model, true, false, protocol.SignOptions{})
		if retryErr == nil {
			resp2, err2 := hostHTTPDo(req.HostCallbackID, retryReq)
			if err2 == nil {
				raw2, _ := io.ReadAll(io.LimitReader(resp2.Body, 8<<20))
				_ = resp2.Body.Close()
				resp, rawResp = resp2, raw2
			}
		}
	}
	if msg := protocol.UpstreamChatError(resp.StatusCode, rawResp); msg != "" {
		code := resp.StatusCode
		if code < 400 {
			code = http.StatusBadGateway
		}
		return errorEnvelope("upstream_error", "chat "+msg, code), nil
	}
	return okEnvelope(pluginapi.ExecutorResponse{
		Payload: rawResp,
		Headers: http.Header{"Content-Type": []string{"application/json"}},
	})
}

// authPrefix is the CPA model prefix configured for this auth. CPA reads it
// from the auth file's "prefix" key, and the same key comes back in the
// executor's AuthMetadata and in StorageJSON.
func authPrefix(meta map[string]any, attrs map[string]string, storage []byte) string {
	if p, ok := meta["prefix"].(string); ok && strings.TrimSpace(p) != "" {
		return p
	}
	if p := strings.TrimSpace(attrs["prefix"]); p != "" {
		return p
	}
	return jsonString(storage, "prefix")
}

func routeMissed(body []byte) bool {
	s := string(body)
	return strings.Contains(s, "InferHub.002002009") || strings.Contains(s, "Route missed") || strings.Contains(s, "not registered")
}

func executeStream(callbackID, pluginStreamID string, httpReq *http.Request, retryBenefit func() (*http.Request, error)) ([]byte, error) {
	status, headers, hostStreamID, buffered, err := hostHTTPDoStream(callbackID, httpReq)
	if err != nil {
		return errorEnvelope("executor_error", err.Error(), http.StatusBadGateway), nil
	}
	// do_stream may return only status, headers, and a stream id. The route-miss
	// body is then the first host.http.stream_read payload, not chunks.
	if status == http.StatusNotFound && len(buffered) == 0 && hostStreamID != "" {
		payload, _, _ := hostHTTPStreamRead(hostStreamID)
		if len(payload) > 0 {
			buffered = payload
		}
	}
	if status == http.StatusNotFound && routeMissed(buffered) && retryBenefit != nil {
		if retryReq, retryErr := retryBenefit(); retryErr == nil && retryReq != nil {
			if hostStreamID != "" {
				hostHTTPStreamClose(hostStreamID)
			}
			status, headers, hostStreamID, buffered, err = hostHTTPDoStream(callbackID, retryReq)
			if err != nil {
				return errorEnvelope("executor_error", err.Error(), http.StatusBadGateway), nil
			}
		}
	}
	if status >= 400 {
		// The host keeps an opened stream until it is closed. Read the error
		// body if do_stream returned none, then release the stream.
		if hostStreamID != "" {
			if len(buffered) == 0 {
				if payload, _, _ := hostHTTPStreamRead(hostStreamID); len(payload) > 0 {
					buffered = payload
				}
			}
			hostHTTPStreamClose(hostStreamID)
		}
		return errorEnvelope("upstream_error", fmt.Sprintf("chat stream http=%d %s", status, truncate(string(buffered), 300)), status), nil
	}
	if headers == nil {
		headers = http.Header{}
	}
	if headers.Get("Content-Type") == "" {
		headers.Set("Content-Type", "text/event-stream")
	}

	// Capture the caller that opened the stream before the goroutine is scheduled.
	// A later SetCaller must not retarget reads, emits, or closes.
	if owner := currentCaller(); hostStreamID != "" && pluginStreamID != "" && owner != nil {
		go forwardHostStream(owner, hostStreamID, pluginStreamID)
		return okEnvelope(map[string]any{"headers": headers})
	}

	if pluginStreamID != "" && currentCaller() != nil && len(buffered) > 0 {
		_ = hostStreamEmit(pluginStreamID, buffered)
		hostStreamClose(pluginStreamID, "")
		return okEnvelope(map[string]any{"headers": headers})
	}

	chunks := []pluginapi.ExecutorStreamChunk{{Payload: bytes.Clone(buffered)}}
	return okEnvelope(map[string]any{
		"headers": headers,
		"chunks":  chunks,
	})
}

func forwardHostStream(owner Caller, hostStreamID, pluginStreamID string) {
	if owner == nil {
		return
	}
	defer func() {
		if currentCaller() != owner {
			return
		}
		hostHTTPStreamCloseOn(owner, hostStreamID)
	}()
	defer func() {
		if currentCaller() != owner {
			return
		}
		hostStreamCloseOn(owner, pluginStreamID, "")
	}()
	for {
		if currentCaller() != owner {
			return
		}
		payload, done, err := hostHTTPStreamReadOn(owner, hostStreamID)
		if currentCaller() != owner {
			return
		}
		if len(payload) > 0 {
			if errEmit := hostStreamEmitOn(owner, pluginStreamID, payload); errEmit != nil {
				hostStreamCloseOn(owner, pluginStreamID, errEmit.Error())
				return
			}
		}
		if err != nil {
			hostStreamCloseOn(owner, pluginStreamID, err.Error())
			return
		}
		if done {
			return
		}
	}
}

func handleExecutorHTTP(request []byte) ([]byte, error) {
	var req pluginapi.ExecutorHTTPRequest
	if err := json.Unmarshal(request, &req); err != nil {
		return errorEnvelope("invalid_request", err.Error(), http.StatusBadRequest), nil
	}
	raw := req.StorageJSON
	if len(raw) == 0 {
		raw = jsonBytes(request, "StorageJSON", "storage_json")
	}
	cred, err := protocol.ParseCredential(raw)
	if err != nil {
		return errorEnvelope("executor_error", err.Error(), http.StatusUnauthorized), nil
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	httpReq, err := http.NewRequest(method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return errorEnvelope("executor_error", err.Error(), http.StatusBadRequest), nil
	}
	for k, vs := range req.Headers {
		for _, v := range vs {
			httpReq.Header.Add(k, v)
		}
	}
	protocol.SignRequest(httpReq, req.Body, protocol.SignCredentialFrom(cred), protocol.SignOptions{})
	callbackID := jsonString(request, "host_callback_id", "HostCallbackID")
	resp, err := hostHTTPDo(callbackID, httpReq)
	if err != nil {
		return errorEnvelope("executor_error", err.Error(), http.StatusBadGateway), nil
	}
	defer resp.Body.Close()
	rawResp, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return okEnvelope(pluginapi.ExecutorHTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header.Clone(),
		Body:       rawResp,
	})
}
