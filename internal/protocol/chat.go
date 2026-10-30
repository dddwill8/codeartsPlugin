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
func PrepareChatBody(raw []byte, model string, stream bool, maxOutput int) ([]byte, string, error) {
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
	if n, ok := firstInt(body, "max_tokens", "max_completion_tokens"); ok && n > 0 {
		if maxOutput > 0 && n > maxOutput {
			n = maxOutput
		}
		// A client often copies the context window into max_completion_tokens.
		// InferHub rejects that as an invalid parameter. Without a discovered
		// output limit, omit the field instead of forwarding the oversized value.
		if maxOutput > 0 || n <= defaultMaxOutput {
			out["max_tokens"] = n
		}
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
		out["tools"] = sanitizeTools(choice.tools)
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

// rewriteMessages keeps only the fields InferHub accepts on a message.
// Content arrays, extra roles, and unpaired tool history are flattened or
// dropped. Assistant messages always carry reasoning_content: DeepSeek rejects
// a tool-call replay that omits it.
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
			continue
		}
		role, _ := msg["role"].(string)
		role = strings.ToLower(strings.TrimSpace(role))
		switch role {
		case "system", "developer", "user":
			if role == "developer" {
				role = "system"
			}
			text := flattenContent(msg["content"])
			if strings.TrimSpace(text) == "" {
				continue
			}
			out = append(out, map[string]any{"role": role, "content": text})
		case "assistant":
			wire := map[string]any{"role": "assistant"}
			reasoning, _ := msg["reasoning_content"].(string)
			wire["reasoning_content"] = reasoning
			text := flattenContent(msg["content"])
			if keepCalls[i] {
				wire["tool_calls"] = sanitizeToolCalls(msg["tool_calls"])
				if text == "" {
					wire["content"] = nil
				} else {
					wire["content"] = text
				}
			} else {
				wire["content"] = text
			}
			out = append(out, wire)
		case "tool":
			if !keepResults[i] {
				continue
			}
			text := flattenContent(msg["content"])
			if strings.TrimSpace(text) == "" {
				text = "(no output)"
			}
			wire := map[string]any{"role": "tool", "content": text}
			if id, _ := msg["tool_call_id"].(string); id != "" {
				wire["tool_call_id"] = id
			}
			if name, _ := msg["name"].(string); strings.TrimSpace(name) != "" {
				wire["name"] = name
			}
			out = append(out, wire)
		default:
			text := flattenContent(msg["content"])
			if strings.TrimSpace(text) == "" {
				continue
			}
			out = append(out, map[string]any{"role": "user", "content": text})
		}
	}
	return out, nil
}

func flattenContent(raw any) string {
	switch v := raw.(type) {
	case nil:
		return ""
	case string:
		return v
	case []any:
		var b strings.Builder
		for _, item := range v {
			part, _ := item.(map[string]any)
			if part == nil {
				continue
			}
			text, _ := part["text"].(string)
			if text == "" {
				text, _ = part["content"].(string)
			}
			if text == "" {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte('\n')
			}
			b.WriteString(text)
		}
		return b.String()
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(raw)
	}
}

func sanitizeToolCalls(raw any) []any {
	calls, _ := raw.([]any)
	out := make([]any, 0, len(calls))
	for _, item := range calls {
		obj, _ := item.(map[string]any)
		if obj == nil {
			continue
		}
		fn, _ := obj["function"].(map[string]any)
		if fn == nil {
			continue
		}
		name, _ := fn["name"].(string)
		args := "{}"
		switch v := fn["arguments"].(type) {
		case string:
			if strings.TrimSpace(v) != "" {
				args = v
			}
		default:
			if v != nil {
				if encoded, err := json.Marshal(v); err == nil {
					args = string(encoded)
				}
			}
		}
		wire := map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":      name,
				"arguments": args,
			},
		}
		if id, _ := obj["id"].(string); id != "" {
			wire["id"] = id
		}
		out = append(out, wire)
	}
	return out
}

func sanitizeTools(tools []any) []any {
	out := make([]any, 0, len(tools))
	for _, item := range tools {
		obj, _ := item.(map[string]any)
		fn, _ := obj["function"].(map[string]any)
		if fn == nil {
			continue
		}
		name, _ := fn["name"].(string)
		if strings.TrimSpace(name) == "" {
			continue
		}
		wireFn := map[string]any{"name": name}
		if desc, _ := fn["description"].(string); strings.TrimSpace(desc) != "" {
			wireFn["description"] = desc
		}
		if params, ok := fn["parameters"]; ok && params != nil {
			wireFn["parameters"] = sanitizeSchema(params)
		} else {
			wireFn["parameters"] = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		out = append(out, map[string]any{"type": "function", "function": wireFn})
	}
	return out
}

// sanitizeSchema keeps the structure a model needs to call a tool and folds
// constraints InferHub rejects into the description.
func sanitizeSchema(raw any) any {
	switch v := raw.(type) {
	case map[string]any:
		out := map[string]any{}
		if typ := schemaType(v); typ != "" {
			out["type"] = typ
		}
		if desc := schemaDescription(v); desc != "" {
			out["description"] = desc
		}
		if props, _ := v["properties"].(map[string]any); len(props) > 0 {
			clean := make(map[string]any, len(props))
			for name, prop := range props {
				clean[name] = sanitizeSchema(prop)
			}
			out["properties"] = clean
		}
		if req := stringList(v["required"]); len(req) > 0 {
			out["required"] = req
		}
		if items, ok := v["items"]; ok && items != nil {
			out["items"] = sanitizeSchema(items)
		}
		if len(out) == 0 {
			out["type"] = "object"
		}
		return out
	case []any:
		if len(v) == 0 {
			return map[string]any{"type": "object"}
		}
		return sanitizeSchema(v[0])
	default:
		return map[string]any{"type": "object"}
	}
}

func schemaType(v map[string]any) string {
	if s, _ := v["type"].(string); s != "" {
		return s
	}
	if types := stringList(v["type"]); len(types) > 0 {
		return types[0]
	}
	for _, key := range []string{"anyOf", "oneOf", "allOf"} {
		list, _ := v[key].([]any)
		for _, item := range list {
			obj, _ := item.(map[string]any)
			if obj == nil {
				continue
			}
			if typ := schemaType(obj); typ != "" {
				return typ
			}
		}
	}
	return ""
}

func schemaDescription(v map[string]any) string {
	desc, _ := v["description"].(string)
	var notes []string
	if values := append(stringList(v["enum"]), constString(v["const"])...); len(values) > 0 {
		notes = append(notes, "allowed: "+strings.Join(values, ", "))
	}
	for _, key := range []string{"anyOf", "oneOf", "allOf"} {
		list, _ := v[key].([]any)
		for _, item := range list {
			obj, _ := item.(map[string]any)
			if obj == nil {
				continue
			}
			if nested := schemaDescription(obj); nested != "" && nested != desc {
				notes = append(notes, nested)
			}
		}
	}
	if len(notes) == 0 {
		return strings.TrimSpace(desc)
	}
	if strings.TrimSpace(desc) == "" {
		return strings.Join(notes, "; ")
	}
	return strings.TrimSpace(desc) + " (" + strings.Join(notes, "; ") + ")"
}

func constString(v any) []string {
	switch n := v.(type) {
	case nil:
		return nil
	case string:
		if n == "" {
			return nil
		}
		return []string{n}
	default:
		raw, err := json.Marshal(n)
		if err != nil {
			return nil
		}
		return []string{string(raw)}
	}
}

func stringList(v any) []string {
	switch n := v.(type) {
	case []any:
		out := make([]string, 0, len(n))
		for _, item := range n {
			s, _ := item.(string)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return append([]string(nil), n...)
	default:
		return nil
	}
}

const defaultMaxOutput = 8192

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
	return strings.Contains(low, "inferhub.001001005") ||
		strings.Contains(low, "request param is invalid") ||
		strings.Contains(low, "modelarts.81001") ||
		strings.Contains(msg, "API 调用参数有误")
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
