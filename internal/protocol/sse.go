package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// sseTranslator turns a Huawei CodeArts chat body into OpenAI JSON.
// A 2xx body may be one JSON object or SSE lines such as data:{"text":"..."}.
// CPA parses a non-stream payload as one JSON object and prefixes each stream
// emit with "data: " itself, so neither path may forward the raw SSE line.
type sseTranslator struct {
	model string
	id    string
	obj   string

	content   strings.Builder
	reasoning strings.Builder
	finish    string
	usage     json.RawMessage
	tools     map[int]*mergedToolCall
	toolOrder []int
	role      string

	parts          int
	passthrough    bool
	fromSSE        bool
	failed         string
	streamPayloads [][]byte
	streamDone     bool
	sawMessage     bool
}

type mergedToolCall struct {
	index int
	id    string
	typ   string
	name  string
	args  strings.Builder
}

// NormalizeNonStreamBody returns one OpenAI chat completion for a non-stream
// executor payload. Plain JSON is returned unchanged. SSE is aggregated.
func NormalizeNonStreamBody(body []byte, model string) ([]byte, error) {
	tr := &sseTranslator{model: model}
	if err := tr.feed(body, true); err != nil {
		return nil, err
	}
	if tr.failed != "" {
		return nil, fmt.Errorf("%s", tr.failed)
	}
	if tr.passthrough {
		return append([]byte(nil), bytes.TrimSpace(body)...), nil
	}
	if tr.parts == 0 {
		return nil, fmt.Errorf("chat body is not json or sse")
	}
	return tr.completion()
}

// TranslateStreamChunk converts one upstream read into JSON objects for
// host.stream.emit. The caller must not add a "data:" prefix. done is true
// when the upstream sent the SSE terminator or the read was a finished JSON
// object. An upstream error_code returns an error instead of a chunk.
func TranslateStreamChunk(chunk []byte, model string) (payloads [][]byte, done bool, err error) {
	tr := &sseTranslator{model: model}
	if err := tr.feed(chunk, false); err != nil {
		return nil, false, err
	}
	if tr.failed != "" {
		return nil, true, fmt.Errorf("%s", tr.failed)
	}
	return tr.streamPayloads, tr.streamDone, nil
}

func (tr *sseTranslator) feed(chunk []byte, aggregate bool) error {
	text := string(chunk)
	if strings.TrimSpace(text) == "" {
		return nil
	}
	if !looksLikeSSE(text) {
		if aggregate && bytes.Contains(chunk, []byte("\ndata:")) {
			return fmt.Errorf("chat sse data is not json")
		}
		return tr.feedJSON(bytes.TrimSpace(chunk), aggregate)
	}
	for _, line := range splitSSELines(text) {
		line = strings.TrimRight(line, "\r")
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, ":") {
			continue
		}
		if !strings.HasPrefix(trim, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(trim, "data:"))
		if data == "" {
			continue
		}
		if data == "[DONE]" {
			tr.streamDone = true
			continue
		}
		tr.fromSSE = true
		if err := tr.feedJSON([]byte(data), aggregate); err != nil {
			return err
		}
	}
	return nil
}

func looksLikeSSE(text string) bool {
	for _, line := range splitSSELines(text) {
		trim := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if trim == "" || strings.HasPrefix(trim, ":") {
			continue
		}
		if strings.HasPrefix(trim, "data:") || strings.HasPrefix(trim, "event:") {
			return true
		}
	}
	return false
}

func splitSSELines(text string) []string {
	return strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
}

func (tr *sseTranslator) feedJSON(raw []byte, aggregate bool) error {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		if tr.parts == 0 && !aggregate {
			return fmt.Errorf("chat stream chunk is not json")
		}
		return fmt.Errorf("chat sse data is not json")
	}
	if msg := upstreamObjectError(obj); msg != "" {
		tr.failed = msg
		return nil
	}
	tr.parts++
	if aggregate && !tr.fromSSE && tr.parts == 1 && !huaweiTextEvent(obj) {
		tr.passthrough = true
		return nil
	}
	tr.absorb(obj)
	if !aggregate {
		payload, err := tr.streamChunk(obj)
		if err != nil {
			return err
		}
		if len(payload) > 0 {
			tr.streamPayloads = append(tr.streamPayloads, payload)
		}
	}
	return nil
}

func huaweiTextEvent(obj map[string]any) bool {
	_, text := obj["text"]
	_, choices := obj["choices"]
	return text && !choices
}

func upstreamObjectError(obj map[string]any) string {
	code, _ := obj["error_code"].(string)
	code = strings.TrimSpace(code)
	if code == "" || code == "0" || code == "0000" {
		return ""
	}
	msg, _ := obj["error_msg"].(string)
	if msg == "" {
		msg, _ = obj["error"].(string)
	}
	return strings.TrimSpace(code + " " + msg)
}

func (tr *sseTranslator) absorb(obj map[string]any) {
	if id, _ := obj["id"].(string); id != "" && tr.id == "" {
		tr.id = id
	}
	if model, _ := obj["model"].(string); model != "" {
		tr.model = model
	}
	if object, _ := obj["object"].(string); object != "" && tr.obj == "" {
		tr.obj = object
	}
	if usage, ok := obj["usage"]; ok && usage != nil {
		if raw, err := json.Marshal(usage); err == nil {
			tr.usage = raw
		}
	}
	if text, _ := obj["text"].(string); text != "" {
		tr.content.WriteString(text)
		if tr.role == "" {
			tr.role = "assistant"
		}
	}
	choices, _ := obj["choices"].([]any)
	for _, item := range choices {
		choice, _ := item.(map[string]any)
		if choice == nil {
			continue
		}
		if reason, _ := choice["finish_reason"].(string); reason != "" {
			tr.finish = reason
		}
		msg, _ := choice["message"].(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		if msg != nil {
			tr.sawMessage = true
			tr.absorbMessage(msg)
		}
		if delta != nil && !tr.sawMessage {
			tr.absorbMessage(delta)
		}
	}
}

func (tr *sseTranslator) absorbMessage(msg map[string]any) {
	if msg == nil {
		return
	}
	if role, _ := msg["role"].(string); role != "" {
		tr.role = role
	}
	if content, _ := msg["content"].(string); content != "" {
		tr.content.WriteString(content)
	}
	if reasoning, _ := msg["reasoning_content"].(string); reasoning != "" {
		tr.reasoning.WriteString(reasoning)
	}
	tools, _ := msg["tool_calls"].([]any)
	for i, item := range tools {
		call, _ := item.(map[string]any)
		if call == nil {
			continue
		}
		index := i
		if n, ok := call["index"].(float64); ok {
			index = int(n)
		}
		merged := tr.tools[index]
		if merged == nil {
			merged = &mergedToolCall{index: index}
			if tr.tools == nil {
				tr.tools = map[int]*mergedToolCall{}
			}
			tr.tools[index] = merged
			tr.toolOrder = append(tr.toolOrder, index)
		}
		if id, _ := call["id"].(string); id != "" {
			merged.id = id
		}
		if typ, _ := call["type"].(string); typ != "" {
			merged.typ = typ
		}
		fn, _ := call["function"].(map[string]any)
		if fn == nil {
			continue
		}
		if name, _ := fn["name"].(string); name != "" {
			merged.name = name
		}
		if args, _ := fn["arguments"].(string); args != "" {
			merged.args.WriteString(args)
		}
	}
}

func (tr *sseTranslator) streamChunk(obj map[string]any) ([]byte, error) {
	if _, ok := obj["choices"]; ok {
		out := cloneMap(obj)
		if _, ok := out["object"]; !ok {
			out["object"] = "chat.completion.chunk"
		}
		if _, ok := out["model"]; !ok && tr.model != "" {
			out["model"] = tr.model
		}
		return json.Marshal(out)
	}
	text, _ := obj["text"].(string)
	reasoning, _ := obj["reasoning_content"].(string)
	reason, _ := obj["finish_reason"].(string)
	if text == "" && reasoning == "" && reason == "" {
		return nil, nil
	}
	delta := map[string]any{}
	if text != "" {
		delta["content"] = text
	}
	if reasoning != "" {
		delta["reasoning_content"] = reasoning
	}
	choice := map[string]any{"index": 0, "delta": delta}
	if reason != "" {
		choice["finish_reason"] = reason
	}
	out := map[string]any{
		"id":      tr.chunkID(),
		"object":  "chat.completion.chunk",
		"created": time.Now().Unix(),
		"choices": []any{choice},
	}
	if tr.model != "" {
		out["model"] = tr.model
	}
	return json.Marshal(out)
}

func (tr *sseTranslator) completion() ([]byte, error) {
	message := map[string]any{"role": "assistant"}
	if tr.role != "" {
		message["role"] = tr.role
	}
	message["content"] = tr.content.String()
	if tr.reasoning.Len() > 0 {
		message["reasoning_content"] = tr.reasoning.String()
	}
	if len(tr.toolOrder) > 0 {
		calls := make([]any, 0, len(tr.toolOrder))
		for _, index := range tr.toolOrder {
			call := tr.tools[index]
			item := map[string]any{
				"index": index,
				"id":    call.id,
				"type":  "function",
				"function": map[string]any{
					"name":      call.name,
					"arguments": call.args.String(),
				},
			}
			if call.typ != "" {
				item["type"] = call.typ
			}
			calls = append(calls, item)
		}
		message["tool_calls"] = calls
	}
	finish := tr.finish
	if finish == "" {
		finish = "stop"
	}
	object := "chat.completion"
	if tr.obj == "chat.completion" {
		object = tr.obj
	}
	out := map[string]any{
		"id":      tr.chunkID(),
		"object":  object,
		"created": time.Now().Unix(),
		"choices": []any{map[string]any{
			"index":         0,
			"message":       message,
			"finish_reason": finish,
		}},
	}
	if tr.model != "" {
		out["model"] = tr.model
	}
	if len(tr.usage) > 0 {
		var usage any
		if json.Unmarshal(tr.usage, &usage) == nil {
			out["usage"] = usage
		}
	}
	return json.Marshal(out)
}

func (tr *sseTranslator) chunkID() string {
	if tr.id != "" {
		return tr.id
	}
	return "chatcmpl-codearts"
}

func cloneMap(in map[string]any) map[string]any {
	raw, err := json.Marshal(in)
	if err != nil {
		return in
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil || out == nil {
		return in
	}
	return out
}
