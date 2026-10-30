package dispatch

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/dddwill8/codeartsPlugin/internal/protocol"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	managementReasoningRoute = "/codearts/reasoning"
	managementReasoningFull  = "/v0/management" + managementReasoningRoute
)

type authFileRef struct {
	Name  string
	Index string
	JSON  []byte
}

type reasoningView struct {
	OK          bool                         `json:"ok"`
	Message     string                       `json:"message,omitempty"`
	Passthrough bool                         `json:"passthrough"`
	Saved       bool                         `json:"saved"`
	Levels      []string                     `json:"levels"`
	Targets     []string                     `json:"targets"`
	Models      []string                     `json:"models"`
	Routes      map[string]map[string]string `json:"routes"`
	Account     string                       `json:"account,omitempty"`
	Accounts    []reasoningAccount           `json:"accounts,omitempty"`
}

type reasoningAccount struct {
	Index string `json:"index"`
	Name  string `json:"name"`
}

func handleReasoning(request []byte, callbackID string) ([]byte, error) {
	var req pluginapi.ManagementRequest
	if len(request) == 0 || json.Unmarshal(request, &req) != nil {
		return errorEnvelope("invalid_management_request", "management request is not JSON", http.StatusBadRequest), nil
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	switch method {
	case http.MethodGet, "":
		return reasoningJSON(http.StatusOK, loadReasoningView(req.Body, callbackID))
	case http.MethodPost:
		return saveReasoning(req.Body, callbackID)
	default:
		return reasoningJSON(http.StatusMethodNotAllowed, reasoningView{Message: "不支持的方法。"})
	}
}

func loadReasoningView(body []byte, callbackID string) reasoningView {
	view := reasoningView{
		OK:          true,
		Passthrough: true,
		Levels:      append([]string(nil), protocol.ReasoningLevels...),
		Targets:     reasoningTargets(),
		Routes:      map[string]map[string]string{},
	}
	files, err := codeArtsAuthFiles()
	if err != nil || len(files) == 0 {
		policy := protocol.DefaultReasoningPolicy()
		view.Passthrough = policy.Passthrough
		view.Routes = policy.Models
		view.Message = "还没有码道账号。登录后才能列出未禁用的模型。"
		return view
	}
	for _, file := range files {
		view.Accounts = append(view.Accounts, reasoningAccount{Index: file.Index, Name: file.Name})
	}
	file := pickAuthFile(files, reasoningIndex(body))
	view.Account = file.Name
	view.Saved = authHasReasoningPolicy(file.JSON)
	policy := protocol.ReasoningPolicyFromAuth(file.JSON)
	view.Passthrough = policy.Passthrough
	if policy.Models != nil {
		view.Routes = policy.Models
	}
	models, msg := enabledModels(file.JSON, callbackID)
	view.Models = models
	if msg != "" {
		view.Message = msg
	}
	return view
}

func saveReasoning(body []byte, callbackID string) ([]byte, error) {
	files, err := codeArtsAuthFiles()
	if err != nil || len(files) == 0 {
		return reasoningJSON(http.StatusBadRequest, reasoningView{Message: "还没有码道账号，不能保存。"})
	}
	var req struct {
		Index       string                       `json:"index"`
		Passthrough *bool                        `json:"passthrough"`
		Routes      map[string]map[string]string `json:"routes"`
	}
	if json.Unmarshal(body, &req) != nil {
		return reasoningJSON(http.StatusBadRequest, reasoningView{Message: "路由不是 JSON。"})
	}
	passthrough := true
	if req.Passthrough != nil {
		passthrough = *req.Passthrough
	}
	rawPolicy, _ := json.Marshal(map[string]any{
		"passthrough": passthrough,
		"models":      req.Routes,
	})
	policy, err := protocol.NormalizeReasoningPolicy(rawPolicy)
	if err != nil {
		return reasoningJSON(http.StatusBadRequest, reasoningView{Message: "路由无法读取。"})
	}
	file := pickAuthFile(files, req.Index)
	stored, err := protocol.PutReasoningPolicy(file.JSON, policy)
	if err != nil || len(stored) == 0 {
		return reasoningJSON(http.StatusBadRequest, reasoningView{Message: "账号文件无法更新。"})
	}
	if err := hostAuthSave(file.Name, stored); err != nil {
		return reasoningJSON(http.StatusBadGateway, reasoningView{Message: "没有写回账号文件。"})
	}
	view := loadReasoningView(body, callbackID)
	view.Saved = true
	view.Message = "已保存。"
	return reasoningJSON(http.StatusOK, view)
}

func enabledModels(raw []byte, callbackID string) ([]string, string) {
	if strings.TrimSpace(callbackID) == "" {
		return nil, ""
	}
	cred, err := protocol.ParseCredential(raw)
	if err != nil || cred.AccessKeyID == "" {
		return nil, "账号里没有可用的临时密钥。"
	}
	client := currentHTTP()
	if currentCaller() != nil && callbackID != "" {
		client = &http.Client{Timeout: 45 * time.Second, Transport: hostCallbackRoundTripper{callbackID: callbackID}}
	}
	infos := protocol.DiscoverModels(client, protocol.SignCredentialFrom(cred), protocol.AccountKey(cred), snapEngineBase(), benefitBase(), currentConfig().BenefitAutoClaim)
	excluded := excludedModels(raw)
	out := make([]string, 0, len(infos))
	seen := map[string]struct{}{}
	for _, info := range infos {
		id := strings.TrimSpace(info.ID)
		key := strings.ToLower(id)
		if id == "" {
			continue
		}
		if _, skip := excluded[key]; skip {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, id)
	}
	if len(out) == 0 {
		return nil, "没有发现未禁用的模型。"
	}
	return out, ""
}

func excludedModels(raw []byte) map[string]struct{} {
	var obj struct {
		Excluded []string `json:"excluded_models"`
	}
	_ = json.Unmarshal(raw, &obj)
	out := map[string]struct{}{}
	for _, id := range obj.Excluded {
		id = strings.ToLower(strings.TrimSpace(id))
		if id != "" {
			out[id] = struct{}{}
		}
	}
	return out
}

func reasoningIndex(body []byte) string {
	var obj struct {
		Index string `json:"index"`
	}
	_ = json.Unmarshal(body, &obj)
	return strings.TrimSpace(obj.Index)
}

func pickAuthFile(files []authFileRef, index string) authFileRef {
	index = strings.TrimSpace(index)
	if index != "" {
		for _, file := range files {
			if file.Index == index {
				return file
			}
		}
	}
	return files[0]
}

func authHasReasoningPolicy(raw []byte) bool {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return false
	}
	saved, ok := obj["reasoning_policy"]
	return ok && len(strings.TrimSpace(string(saved))) > 0 && string(saved) != "null"
}

func reasoningTargets() []string {
	out := []string{protocol.ReasoningKeep, protocol.ReasoningDrop}
	return append(out, protocol.ReasoningLevels...)
}

func reasoningJSON(status int, view reasoningView) ([]byte, error) {
	if view.Levels == nil {
		view.Levels = append([]string(nil), protocol.ReasoningLevels...)
	}
	if view.Targets == nil {
		view.Targets = reasoningTargets()
	}
	if view.Routes == nil {
		view.Routes = map[string]map[string]string{}
	}
	body, err := json.Marshal(view)
	if err != nil {
		return nil, err
	}
	return managementBytes(status, "application/json; charset=utf-8", "", body)
}

func codeArtsAuthFiles() ([]authFileRef, error) {
	if currentCaller() == nil {
		return nil, nil
	}
	listed, err := callHost(pluginabi.MethodHostAuthList, map[string]any{})
	if err != nil {
		return nil, err
	}
	var list struct {
		Files []struct {
			Name      string `json:"name"`
			AuthIndex string `json:"auth_index"`
			Path      string `json:"path"`
		} `json:"files"`
	}
	if json.Unmarshal(listed, &list) != nil {
		return nil, nil
	}
	out := make([]authFileRef, 0, len(list.Files))
	for _, file := range list.Files {
		index := strings.TrimSpace(file.AuthIndex)
		name := strings.TrimSpace(file.Name)
		if index == "" {
			continue
		}
		got, err := callHost(pluginabi.MethodHostAuthGet, map[string]any{"auth_index": index})
		if err != nil {
			continue
		}
		var resp struct {
			JSON json.RawMessage `json:"json"`
		}
		if json.Unmarshal(got, &resp) != nil || len(bytesTrim(resp.JSON)) == 0 {
			continue
		}
		if !protocol.LooksLikeCodeArts(resp.JSON, name) {
			continue
		}
		if name == "" {
			name = "codearts.json"
		}
		out = append(out, authFileRef{Name: name, Index: index, JSON: append([]byte(nil), resp.JSON...)})
	}
	return out, nil
}
