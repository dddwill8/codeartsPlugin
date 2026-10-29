package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeNonStreamBodyPassesThroughJSON(t *testing.T) {
	in := []byte(`{"id":"chatcmpl-test","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	got, err := NormalizeNonStreamBody(in, "GLM-5.3")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(in) {
		t.Fatalf("payload = %s", got)
	}
}

func TestNormalizeNonStreamBodyAggregatesHuaweiText(t *testing.T) {
	in := []byte("data:{\"text\":\"tex\"}\ndata:{\"text\":\"t\"}\ndata: [DONE]\n")
	got, err := NormalizeNonStreamBody(in, "DeepSeek-V4.1-Flash-1017")
	if err != nil {
		t.Fatal(err)
	}
	var obj struct {
		Object  string `json:"object"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			Finish string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatalf("payload is not json: %s", got)
	}
	if obj.Object != "chat.completion" || obj.Model != "DeepSeek-V4.1-Flash-1017" {
		t.Fatalf("object=%q model=%q", obj.Object, obj.Model)
	}
	if len(obj.Choices) != 1 || obj.Choices[0].Message.Content != "text" || obj.Choices[0].Finish != "stop" {
		t.Fatalf("choices = %+v", obj.Choices)
	}
	if strings.Contains(string(got), "data:") {
		t.Fatalf("sse prefix leaked: %s", got)
	}
}

func TestNormalizeNonStreamBodyJoinsOpenAIDeltas(t *testing.T) {
	in := []byte(strings.Join([]string{
		`data: {"id":"c1","choices":[{"delta":{"content":"tex"}}]}`,
		`data: {"choices":[{"delta":{"content":"t"},"finish_reason":"stop"}]}`,
		`data: [DONE]`,
		``,
	}, "\n"))
	got, err := NormalizeNonStreamBody(in, "GLM-5.3")
	if err != nil {
		t.Fatal(err)
	}
	var obj struct {
		ID      string `json:"id"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(got, &obj); err != nil {
		t.Fatalf("payload = %s: %v", got, err)
	}
	if obj.ID != "c1" || len(obj.Choices) != 1 || obj.Choices[0].Message.Content != "text" {
		t.Fatalf("got %+v raw=%s", obj, got)
	}
}

func TestNormalizeNonStreamBodyRejectsSSEError(t *testing.T) {
	in := []byte("data:{\"error_code\":\"InferHub.001001005.400\",\"error_msg\":\"invalid tools\"}\n")
	_, err := NormalizeNonStreamBody(in, "GLM-5.3")
	if err == nil || !strings.Contains(err.Error(), "InferHub.001001005.400") {
		t.Fatalf("err = %v", err)
	}
}

func TestTranslateStreamChunkStripsDataPrefix(t *testing.T) {
	payloads, done, err := TranslateStreamChunk([]byte("data:{\"text\":\"tex\"}\n"), "DeepSeek-V4.1-Flash-1017")
	if err != nil {
		t.Fatal(err)
	}
	if done || len(payloads) != 1 {
		t.Fatalf("done=%v payloads=%d", done, len(payloads))
	}
	if bytesHasPrefixData(payloads[0]) {
		t.Fatalf("payload = %s", payloads[0])
	}
	var obj struct {
		Object string `json:"object"`
		Model  string `json:"model"`
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(payloads[0], &obj); err != nil {
		t.Fatal(err)
	}
	if obj.Object != "chat.completion.chunk" || obj.Model != "DeepSeek-V4.1-Flash-1017" || obj.Choices[0].Delta.Content != "tex" {
		t.Fatalf("chunk = %+v", obj)
	}
}

func TestTranslateStreamChunkDoneAndOpenAI(t *testing.T) {
	raw := []byte(strings.Join([]string{
		`data: {"id":"c1","object":"chat.completion.chunk","choices":[{"delta":{"content":"ok"}}]}`,
		`data: [DONE]`,
		``,
	}, "\n"))
	payloads, done, err := TranslateStreamChunk(raw, "GLM-5.3")
	if err != nil {
		t.Fatal(err)
	}
	if !done || len(payloads) != 1 {
		t.Fatalf("done=%v n=%d", done, len(payloads))
	}
	if !strings.Contains(string(payloads[0]), `"content":"ok"`) || bytesHasPrefixData(payloads[0]) {
		t.Fatalf("payload = %s", payloads[0])
	}
}

func TestTranslateStreamChunkRejectsError(t *testing.T) {
	_, _, err := TranslateStreamChunk([]byte("data:{\"error_code\":\"InferHub.002002009.404\",\"error_msg\":\"Route missed\"}\n"), "GLM-5.3")
	if err == nil || !strings.Contains(err.Error(), "InferHub.002002009.404") {
		t.Fatalf("err = %v", err)
	}
}

func bytesHasPrefixData(b []byte) bool {
	return strings.HasPrefix(strings.TrimSpace(string(b)), "data:")
}
