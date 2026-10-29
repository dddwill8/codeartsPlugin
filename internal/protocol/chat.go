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

// PrepareChatBody rebuilds an OpenAI chat body into the shape InferHub accepts.
// Unknown fields are dropped. A named tool_choice object becomes the string
// "required" with tools reduced to that one function: InferHub rejects the
// object form with InferHub.001001005.400.
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

	out := map[string]any{"stream": stream}
	if model != "" {
		out["model"] = model
	}
	if msgs, ok := body["messages"]; ok {
		rewritten, err := rewriteMessages(msgs)
		if err != nil {
			return nil, "", err
		}
		out["messages"] = rewritten
	}
	if n, ok := firstInt(body, "max_tokens", "max_completion_tokens"); ok {
		out["max_tokens"] = n
	}
	if v, ok := numberField(body, "temperature"); ok {
		out["temperature"] = v
	}
	if v, ok := numberField(body, "top_p"); ok {
		out["top_p"] = v
	}
	if effort, _ := body["reasoning_effort"].(string); strings.TrimSpace(effort) != "" {
		out["reasoning_effort"] = strings.ToLower(strings.TrimSpace(effort))
	}

	tools, _ := body["tools"].([]any)
	choice, err := rewriteToolChoice(body["tool_choice"], tools)
	if err != nil {
		return nil, "", err
	}
	if choice.tools != nil {
		out["tools"] = choice.tools
		out["tool_choice"] = choice.mode
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, "", err
	}
	return encoded, model, nil
}

// toolChoiceResult is the InferHub-safe tools and tool_choice pair.
type toolChoiceResult struct {
	tools []any
	mode  string
}

// rewriteToolChoice keeps string modes and turns a named function object into
// "required" plus that single tool. InferHub accepts only the string form.
func rewriteToolChoice(raw any, tools []any) (toolChoiceResult, error) {
	if len(tools) == 0 {
		return toolChoiceResult{}, nil
	}
	switch choice := raw.(type) {
	case nil:
		return toolChoiceResult{tools: tools, mode: "auto"}, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(choice)) {
		case "none":
			return toolChoiceResult{}, nil
		case "required":
			return toolChoiceResult{tools: tools, mode: "required"}, nil
		default:
			return toolChoiceResult{tools: tools, mode: "auto"}, nil
		}
	case map[string]any:
		name := namedTool(choice)
		if name == "" {
			return toolChoiceResult{tools: tools, mode: "auto"}, nil
		}
		selected, err := selectTool(tools, name)
		if err != nil {
			return toolChoiceResult{}, err
		}
		return toolChoiceResult{tools: []any{selected}, mode: "required"}, nil
	default:
		return toolChoiceResult{tools: tools, mode: "auto"}, nil
	}
}

func namedTool(choice map[string]any) string {
	fn, _ := choice["function"].(map[string]any)
	if fn == nil {
		return ""
	}
	name, _ := fn["name"].(string)
	return strings.TrimSpace(name)
}

func selectTool(tools []any, name string) (any, error) {
	var selected any
	for _, tool := range tools {
		obj, _ := tool.(map[string]any)
		fn, _ := obj["function"].(map[string]any)
		if fn == nil {
			continue
		}
		got, _ := fn["name"].(string)
		if got != name {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("tool_choice function %q is defined more than once", name)
		}
		selected = tool
	}
	if selected == nil {
		return nil, fmt.Errorf("tool_choice function %q is not defined in tools", name)
	}
	return selected, nil
}

// rewriteMessages drops unpaired tool history and fills reasoning_content on
// assistant messages that carry tool_calls. InferHub rejects both shapes.
func rewriteMessages(raw any) ([]any, error) {
	msgs, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("messages must be an array")
	}
	keepCalls, keepResults := pairedToolIndexes(msgs)
	out := make([]any, 0, len(msgs))
	for i, item := range msgs {
		msg, _ := item.(map[string]any)
		if msg == nil {
			out = append(out, item)
			continue
		}
		role, _ := msg["role"].(string)
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "assistant":
			copied := cloneMessage(msg)
			if !keepCalls[i] {
				delete(copied, "tool_calls")
			} else if _, ok := copied["reasoning_content"]; !ok {
				copied["reasoning_content"] = ""
			}
			out = append(out, copied)
		case "tool":
			if keepResults[i] {
				out = append(out, cloneMessage(msg))
			}
		default:
			out = append(out, cloneMessage(msg))
		}
	}
	return out, nil
}

func pairedToolIndexes(msgs []any) (map[int]bool, map[int]bool) {
	resultIndex := map[string]int{}
	for i, item := range msgs {
		msg, _ := item.(map[string]any)
		if msg == nil {
			continue
		}
		role, _ := msg["role"].(string)
		id, _ := msg["tool_call_id"].(string)
		if strings.EqualFold(role, "tool") && id != "" {
			resultIndex[id] = i
		}
	}
	keepCalls := map[int]bool{}
	keepResults := map[int]bool{}
	for i, item := range msgs {
		msg, _ := item.(map[string]any)
		if msg == nil {
			continue
		}
		role, _ := msg["role"].(string)
		if !strings.EqualFold(role, "assistant") {
			continue
		}
		calls, _ := msg["tool_calls"].([]any)
		if len(calls) == 0 {
			continue
		}
		ids := make([]string, 0, len(calls))
		complete := true
		for _, call := range calls {
			obj, _ := call.(map[string]any)
			id, _ := obj["id"].(string)
			if id == "" {
				complete = false
				break
			}
			if _, ok := resultIndex[id]; !ok {
				complete = false
				break
			}
			ids = append(ids, id)
		}
		if !complete {
			continue
		}
		keepCalls[i] = true
		for _, id := range ids {
			keepResults[resultIndex[id]] = true
		}
	}
	return keepCalls, keepResults
}

func cloneMessage(msg map[string]any) map[string]any {
	out := make(map[string]any, len(msg))
	for k, v := range msg {
		out[k] = v
	}
	return out
}

func firstInt(body map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		n, ok := body[key]
		if !ok || n == nil {
			continue
		}
		switch v := n.(type) {
		case float64:
			return int(v), true
		case json.Number:
			i, err := v.Int64()
			if err != nil {
				continue
			}
			return int(i), true
		}
	}
	return 0, false
}

func numberField(body map[string]any, key string) (float64, bool) {
	n, ok := body[key]
	if !ok || n == nil {
		return 0, false
	}
	switch v := n.(type) {
	case float64:
		return v, true
	case json.Number:
		f, err := v.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
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

// ParamInvalid reports InferHub.001001005, a client request-shape rejection.
// Retrying the same body with benefit headers cannot fix it.
func ParamInvalid(msg string) bool {
	low := strings.ToLower(msg)
	return strings.Contains(low, "inferhub.001001005") || strings.Contains(low, "request param is invalid")
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
