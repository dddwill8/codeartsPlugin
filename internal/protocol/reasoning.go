package protocol

import (
	"bytes"
	"encoding/json"
	"strings"
)

const (
	// ReasoningKeep leaves the client's reasoning_effort unchanged.
	ReasoningKeep = "keep"
	// ReasoningDrop removes reasoning_effort before the upstream call.
	ReasoningDrop = "drop"
	// ReasoningUnknown is the route for an effort the table does not list.
	ReasoningUnknown = "unknown"

	reasoningPolicyKey = "reasoning_policy"
)

// ReasoningLevels are the effort names the management page can route.
var ReasoningLevels = []string{"none", "minimal", "low", "medium", "high", "xhigh"}

// ReasoningPolicy decides whether a chat request keeps reasoning_effort.
// Passthrough false drops every value. Otherwise each model map sends a
// source effort to keep, drop, or another level. A missing model or effort
// means keep. The unknown key covers efforts that are not in the table.
type ReasoningPolicy struct {
	Passthrough bool                         `json:"passthrough"`
	Models      map[string]map[string]string `json:"models,omitempty"`
}

// DefaultReasoningPolicy passes effort through, except glm-5.3 none and
// minimal, which ModelArts rejects with 81001. Those become low.
func DefaultReasoningPolicy() ReasoningPolicy {
	return ReasoningPolicy{
		Passthrough: true,
		Models: map[string]map[string]string{
			"glm-5.3": {
				"none":    "low",
				"minimal": "low",
			},
		},
	}
}

// ReasoningPolicyFromAuth reads reasoning_policy from an auth file.
// A missing key uses DefaultReasoningPolicy. A present object is used as
// saved, so an explicit table can undo the glm-5.3 default.
func ReasoningPolicyFromAuth(raw []byte) ReasoningPolicy {
	if len(bytes.TrimSpace(raw)) == 0 {
		return DefaultReasoningPolicy()
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || obj == nil {
		return DefaultReasoningPolicy()
	}
	saved, ok := obj[reasoningPolicyKey]
	if !ok || len(bytes.TrimSpace(saved)) == 0 || string(saved) == "null" {
		return DefaultReasoningPolicy()
	}
	policy, err := NormalizeReasoningPolicy(saved)
	if err != nil {
		return DefaultReasoningPolicy()
	}
	return policy
}

// NormalizeReasoningPolicy checks a saved policy. Targets must be keep,
// drop, or one of ReasoningLevels. An omitted passthrough stays on.
func NormalizeReasoningPolicy(raw []byte) (ReasoningPolicy, error) {
	var in struct {
		Passthrough *bool                        `json:"passthrough"`
		Models      map[string]map[string]string `json:"models"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return ReasoningPolicy{}, err
	}
	out := ReasoningPolicy{Passthrough: true, Models: map[string]map[string]string{}}
	if in.Passthrough != nil {
		out.Passthrough = *in.Passthrough
	}
	for model, routes := range in.Models {
		model = strings.ToLower(strings.TrimSpace(model))
		if model == "" || routes == nil {
			continue
		}
		clean := map[string]string{}
		for src, dst := range routes {
			src = strings.ToLower(strings.TrimSpace(src))
			dst = strings.ToLower(strings.TrimSpace(dst))
			if src == "" || dst == "" || !knownReasoningSource(src) || !knownReasoningTarget(dst) {
				continue
			}
			if dst == ReasoningKeep {
				continue
			}
			clean[src] = dst
		}
		if len(clean) > 0 {
			out.Models[model] = clean
		}
	}
	return out, nil
}

// PutReasoningPolicy stores policy on an auth JSON object and keeps every
// other key, including refresh tokens and CPA fields.
func PutReasoningPolicy(raw []byte, policy ReasoningPolicy) ([]byte, error) {
	base := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &base); err != nil || base == nil {
			return nil, err
		}
	}
	encoded, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	base[reasoningPolicyKey] = encoded
	return json.Marshal(base)
}

// ApplyReasoningPolicy rewrites or removes reasoning_effort on a chat body.
func ApplyReasoningPolicy(body []byte, model string, policy ReasoningPolicy) []byte {
	if len(bytes.TrimSpace(body)) == 0 {
		return body
	}
	var obj map[string]any
	if json.Unmarshal(body, &obj) != nil || obj == nil {
		return body
	}
	effort, _ := obj["reasoning_effort"].(string)
	effort = strings.ToLower(strings.TrimSpace(effort))
	if effort == "" {
		return body
	}
	next, keep := routeReasoning(model, effort, policy)
	if !keep {
		delete(obj, "reasoning_effort")
	} else if next != effort {
		obj["reasoning_effort"] = next
	} else {
		return body
	}
	encoded, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return encoded
}

func routeReasoning(model, effort string, policy ReasoningPolicy) (string, bool) {
	if !policy.Passthrough {
		return "", false
	}
	routes := policy.Models[strings.ToLower(strings.TrimSpace(model))]
	target, ok := routes[effort]
	if !ok {
		target = routes[ReasoningUnknown]
	}
	target = strings.ToLower(strings.TrimSpace(target))
	switch target {
	case "", ReasoningKeep:
		return effort, true
	case ReasoningDrop:
		return "", false
	default:
		if !knownReasoningTarget(target) {
			return effort, true
		}
		return target, true
	}
}

func knownReasoningSource(name string) bool {
	if name == ReasoningUnknown {
		return true
	}
	for _, level := range ReasoningLevels {
		if name == level {
			return true
		}
	}
	return false
}

func knownReasoningTarget(name string) bool {
	if name == ReasoningKeep || name == ReasoningDrop {
		return true
	}
	for _, level := range ReasoningLevels {
		if name == level {
			return true
		}
	}
	return false
}
