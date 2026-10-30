package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDefaultReasoningRoutesGLMNoneAndMinimalToLow(t *testing.T) {
	policy := DefaultReasoningPolicy()
	body := []byte(`{"model":"glm-5.3","reasoning_effort":"minimal","messages":[{"role":"user","content":"ping"}]}`)
	got := ApplyReasoningPolicy(body, "GLM-5.3", policy)
	if !strings.Contains(string(got), `"reasoning_effort":"low"`) {
		t.Fatalf("body = %s", got)
	}
	none := ApplyReasoningPolicy([]byte(`{"reasoning_effort":"none"}`), "glm-5.3", policy)
	if !strings.Contains(string(none), `"reasoning_effort":"low"`) {
		t.Fatalf("none = %s", none)
	}
	low := ApplyReasoningPolicy([]byte(`{"reasoning_effort":"low"}`), "glm-5.3", policy)
	if string(low) != `{"reasoning_effort":"low"}` {
		t.Fatalf("low changed: %s", low)
	}
}

func TestReasoningPassthroughOffDropsEveryEffort(t *testing.T) {
	policy := DefaultReasoningPolicy()
	policy.Passthrough = false
	got := ApplyReasoningPolicy([]byte(`{"reasoning_effort":"high","model":"kimi-k3"}`), "kimi-k3", policy)
	if strings.Contains(string(got), "reasoning_effort") {
		t.Fatalf("effort kept: %s", got)
	}
}

func TestSavedPolicyCanUndoGLMDefault(t *testing.T) {
	raw := []byte(`{"type":"codearts","access_key_id":"AK","reasoning_policy":{"passthrough":true,"models":{"glm-5.3":{"minimal":"keep"}}}}`)
	policy := ReasoningPolicyFromAuth(raw)
	got := ApplyReasoningPolicy([]byte(`{"reasoning_effort":"minimal"}`), "glm-5.3", policy)
	if !strings.Contains(string(got), `"reasoning_effort":"minimal"`) {
		t.Fatalf("saved keep was overridden: %s", got)
	}
}

func TestMissingPolicyUsesDefault(t *testing.T) {
	policy := ReasoningPolicyFromAuth([]byte(`{"type":"codearts","access_key_id":"AK"}`))
	got := ApplyReasoningPolicy([]byte(`{"reasoning_effort":"minimal"}`), "glm-5.3", policy)
	if !strings.Contains(string(got), `"reasoning_effort":"low"`) {
		t.Fatalf("default not applied: %s", got)
	}
	other := ApplyReasoningPolicy([]byte(`{"reasoning_effort":"minimal"}`), "kimi-k3", policy)
	if !strings.Contains(string(other), `"reasoning_effort":"minimal"`) {
		t.Fatalf("other model changed: %s", other)
	}
}

func TestPutReasoningPolicyKeepsAuthFields(t *testing.T) {
	original := []byte(`{"type":"codearts","access_key_id":"AK","prefix":"codearts","excluded_models":["glm-5.2"]}`)
	policy := DefaultReasoningPolicy()
	policy.Passthrough = false
	stored, err := PutReasoningPolicy(original, policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"prefix":"codearts"`, `"access_key_id":"AK"`, `"glm-5.2"`, `"passthrough":false`} {
		if !strings.Contains(string(stored), key) {
			t.Fatalf("stored missing %s: %s", key, stored)
		}
	}
	merged, err := MergeCredential(stored, Credential{Type: Provider, AccessKeyID: "AK2", SecretAccessKey: "sk", SecurityToken: "st", RefreshToken: "rt"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(merged), `"reasoning_policy"`) || !strings.Contains(string(merged), `"access_key_id":"AK2"`) {
		t.Fatalf("refresh dropped the policy: %s", merged)
	}
}

func TestNormalizeDropsUnknownTargets(t *testing.T) {
	raw := []byte(`{"passthrough":true,"models":{"glm-5.3":{"minimal":"nope","low":"drop","unknown":"keep"}}}`)
	policy, err := NormalizeReasoningPolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	routes := policy.Models["glm-5.3"]
	if _, ok := routes["minimal"]; ok || routes["low"] != ReasoningDrop {
		t.Fatalf("routes = %#v", routes)
	}
	if _, ok := routes[ReasoningUnknown]; ok {
		t.Fatalf("keep should be omitted: %#v", routes)
	}
	var encoded map[string]any
	if json.Unmarshal(raw, &encoded) != nil {
		t.Fatal("fixture")
	}
}
