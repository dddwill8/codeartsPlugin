package dispatch

import (
	"encoding/json"
	"strings"

	"github.com/dddwill8/codeartsPlugin/internal/protocol"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

type lifecycleRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type registration struct {
	SchemaVersion uint32                   `json:"schema_version"`
	Metadata      pluginapi.Metadata       `json:"metadata"`
	Capabilities  registrationCapabilities `json:"capabilities"`
}

type registrationCapabilities struct {
	ModelRegistrar        bool                         `json:"model_registrar"`
	ModelProvider         bool                         `json:"model_provider"`
	AuthProvider          bool                         `json:"auth_provider"`
	Executor              bool                         `json:"executor"`
	ExecutorModelScope    pluginapi.ExecutorModelScope `json:"executor_model_scope"`
	ExecutorInputFormats  []string                     `json:"executor_input_formats,omitempty"`
	ExecutorOutputFormats []string                     `json:"executor_output_formats,omitempty"`
	ManagementAPI         bool                         `json:"management_api"`
}

type identifierResponse struct {
	Identifier string `json:"identifier"`
}

// Handle is the shipped C ABI method switch (JSON in / JSON envelope out).
func Handle(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return handleRegister(request)
	case pluginabi.MethodPluginQuiesce, pluginabi.MethodPluginShutdown:
		stopCallbackListener()
		return okEnvelope(map[string]any{})
	case pluginabi.MethodModelRegister:
		return okEnvelope(pluginapi.ModelRegistrationResponse{Provider: protocol.Provider, Models: pluginModels(nil)})
	case pluginabi.MethodModelStatic:
		return okEnvelope(pluginapi.ModelResponse{Provider: protocol.Provider, Models: pluginModels(nil)})
	case pluginabi.MethodModelForAuth:
		return handleModelsForAuth(request)
	case pluginabi.MethodAuthIdentifier, pluginabi.MethodExecutorIdentifier:
		return okEnvelope(identifierResponse{Identifier: protocol.Provider})
	case pluginabi.MethodAuthParse:
		return handleAuthParse(request)
	case pluginabi.MethodAuthLoginStart:
		return handleLoginStart(request)
	case pluginabi.MethodAuthLoginPoll:
		return handleLoginPoll(request)
	case pluginabi.MethodAuthRefresh:
		return handleRefresh(request)
	case pluginabi.MethodExecutorExecute:
		return handleExecute(request, false)
	case pluginabi.MethodExecutorExecuteStream:
		return handleExecute(request, true)
	case pluginabi.MethodExecutorCountTokens:
		return okEnvelope(pluginapi.ExecutorResponse{Payload: []byte(`{"total_tokens":0}`)})
	case pluginabi.MethodExecutorHTTPRequest:
		return handleExecutorHTTP(request)
	case pluginabi.MethodManagementRegister:
		return handleManagementRegister(request)
	case pluginabi.MethodManagementHandle:
		return handleManagement(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method, 0), nil
	}
}

func handleRegister(request []byte) ([]byte, error) {
	var req lifecycleRequest
	if len(request) > 0 {
		_ = json.Unmarshal(request, &req)
	}
	cfg := parseConfigYAML(req.ConfigYAML)
	setConfig(cfg)
	ensureCallbackListener(cfg)
	return okEnvelope(pluginRegistration())
}

func pluginRegistration() registration {
	return registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             protocol.PluginID,
			Version:          protocol.PluginVersion,
			Author:           protocol.PluginAuthor,
			GitHubRepository: "https://github.com/dddwill8/codeartsPlugin",
			ConfigFields:     configFields(),
		},
		Capabilities: registrationCapabilities{
			ModelRegistrar:        true,
			ModelProvider:         true,
			AuthProvider:          true,
			Executor:              true,
			ExecutorModelScope:    pluginapi.ExecutorModelScopeBoth,
			ExecutorInputFormats:  []string{"chat-completions"},
			ExecutorOutputFormats: []string{"chat-completions"},
			ManagementAPI:         true,
		},
	}
}

func pluginModels(infos []protocol.ModelInfo) []pluginapi.ModelInfo {
	out := make([]pluginapi.ModelInfo, 0, len(infos))
	for _, m := range infos {
		id := strings.TrimSpace(m.ID)
		if id == "" {
			continue
		}
		name := m.Name
		if name == "" {
			name = id
		}
		out = append(out, pluginapi.ModelInfo{
			ID:                         id,
			Object:                     "model",
			OwnedBy:                    protocol.Provider,
			DisplayName:                name,
			Name:                       name,
			Description:                m.Desc,
			ContextLength:              m.ContextWindow,
			MaxCompletionTokens:        m.MaxTokens,
			SupportedGenerationMethods: []string{"chat"},
			UserDefined:                true,
		})
	}
	return out
}

func okEnvelope(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}

func errorEnvelope(code, message string, httpStatus int) []byte {
	raw, _ := json.Marshal(envelope{
		OK: false,
		Error: &envelopeError{
			Code:       code,
			Message:    message,
			HTTPStatus: httpStatus,
		},
	})
	return raw
}

func jsonString(raw []byte, names ...string) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	for _, name := range names {
		if v, ok := m[name].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func jsonBytes(raw []byte, names ...string) []byte {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	for _, name := range names {
		if v, ok := m[name]; ok && len(v) > 0 && string(v) != "null" {
			var b []byte
			if err := json.Unmarshal(v, &b); err == nil {
				return b
			}
			return append([]byte(nil), v...)
		}
	}
	return nil
}

func jsonBool(raw []byte, names ...string) bool {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	for _, name := range names {
		switch v := m[name].(type) {
		case bool:
			return v
		case string:
			return v == "true" || v == "1"
		}
	}
	return false
}
