package dispatch

import (
	"github.com/dddwill8/codeartsPlugin/internal/protocol"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func handleModelsForAuth(request []byte) ([]byte, error) {
	raw := jsonBytes(request, "StorageJSON", "storage_json")
	c, err := protocol.ParseCredential(raw)
	if err != nil || c.AccessKeyID == "" {
		return okEnvelope(pluginapi.ModelResponse{Provider: protocol.Provider, Models: pluginModels(nil)})
	}
	cfg := currentConfig()
	infos := protocol.DiscoverModels(
		currentHTTP(),
		protocol.SignCredentialFrom(c),
		protocol.AccountKey(c),
		snapEngineBase(),
		benefitBase(),
		cfg.BenefitAutoClaim,
	)
	return okEnvelope(pluginapi.ModelResponse{Provider: protocol.Provider, Models: pluginModels(infos)})
}
