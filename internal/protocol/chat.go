package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ChatTarget is the upstream chat-completions URL.
func ChatTarget(snapBase string) string {
	if snapBase == "" {
		snapBase = SnapEngineAPIHost
	}
	return strings.TrimRight(snapBase, "/") + EpChatV2
}

// PrepareChatBody ensures the OpenAI-shaped body has the canonical model and stream flag.
func PrepareChatBody(raw []byte, model string, stream bool) ([]byte, string, error) {
	var body map[string]any
	if len(bytes.TrimSpace(raw)) == 0 {
		body = map[string]any{}
	} else if err := json.Unmarshal(raw, &body); err != nil {
		return nil, "", fmt.Errorf("decode chat body: %w", err)
	}
	if body == nil {
		body = map[string]any{}
	}
	if model == "" {
		if m, _ := body["model"].(string); m != "" {
			model = m
		}
	}
	model = CanonicalModel(model)
	if model != "" {
		body["model"] = model
	}
	body["stream"] = stream
	out, err := json.Marshal(body)
	if err != nil {
		return nil, "", err
	}
	return out, model, nil
}

// ApplyBenefitHeaders sets maas_type / model-id / model-name on req when benefit is true.
// These headers must be present before SignRequest so they enter SignedHeaders.
func ApplyBenefitHeaders(req *http.Request, benefit bool, modelID string) {
	if req == nil || !benefit || strings.TrimSpace(modelID) == "" {
		return
	}
	req.Header.Set(HeaderMaasType, MaasBenefit)
	req.Header.Set(HeaderModelID, modelID)
	req.Header.Set(HeaderModelName, modelID)
}

// NewChatRequest builds a signed POST to /api/v2/chat/completions.
func NewChatRequest(target string, body []byte, cred SignCredential, model string, benefit, stream bool, opts SignOptions) (*http.Request, error) {
	if target == "" {
		target = ChatTarget("")
	}
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	accept := "application/json"
	if stream {
		accept = "text/event-stream"
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", accept)
	req.Header.Set("X-Language", "zh-cn")
	req.Header.Set("app-id", "CodeAgent3.0")
	req.Header.Set("is_confidential", "false")
	req.Header.Set("x-snap-traceid", RandomHexOrTime(8))
	if cred.SecurityToken != "" {
		req.Header.Set("x-auth-token", cred.SecurityToken)
	}
	ApplyBenefitHeaders(req, benefit, model)
	SignRequest(req, body, cred, opts)
	return req, nil
}

// PostChatCompletions signs and sends the OpenAI-shaped body to the v2 endpoint.
func PostChatCompletions(client *http.Client, target string, body []byte, cred SignCredential, model string, benefit, stream bool, opts SignOptions) (*http.Response, error) {
	req, err := NewChatRequest(target, body, cred, model, benefit, stream, opts)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	return client.Do(req)
}

// UpstreamChatError returns a non-empty message when Huawei wrapped a failure
// in a 2xx JSON body (e.g. error_code 4004 benefit not found).
func UpstreamChatError(status int, body []byte) string {
	if status >= 400 {
		return fmt.Sprintf("http=%d %s", status, truncateRunes(string(body), 240))
	}
	var obj struct {
		ErrorCode string          `json:"error_code"`
		ErrorMsg  string          `json:"error_msg"`
		Error     string          `json:"error"`
		Choices   json.RawMessage `json:"choices"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return ""
	}
	if obj.ErrorCode != "" && obj.ErrorCode != "0000" && obj.ErrorCode != "0" {
		msg := obj.ErrorMsg
		if msg == "" {
			msg = obj.Error
		}
		return strings.TrimSpace(obj.ErrorCode + " " + msg)
	}
	return ""
}

func truncateRunes(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ReadAllLimited reads at most n bytes from r.
func ReadAllLimited(r io.Reader, n int64) ([]byte, error) {
	if n <= 0 {
		n = 4 << 20
	}
	return io.ReadAll(io.LimitReader(r, n))
}
