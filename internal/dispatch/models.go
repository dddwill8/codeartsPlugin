package dispatch

import (
	"net/http"
	"time"

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
	client := currentHTTP()
	callbackID := jsonString(request, "host_callback_id", "HostCallbackID")
	if currentCaller() != nil && callbackID != "" {
		// Fresh client: do not install this transport on currentHTTP, or a
		// hostHTTPDo fallback would call RoundTrip again.
		client = &http.Client{
			Timeout:   45 * time.Second,
			Transport: hostCallbackRoundTripper{callbackID: callbackID},
		}
	}
	infos := protocol.DiscoverModels(
		client,
		protocol.SignCredentialFrom(c),
		protocol.AccountKey(c),
		snapEngineBase(),
		benefitBase(),
		cfg.BenefitAutoClaim,
	)
	return okEnvelope(pluginapi.ModelResponse{Provider: protocol.Provider, Models: pluginModels(infos)})
}

// hostCallbackRoundTripper sends catalog GETs and the benefit claim POST through host.http.do.
type hostCallbackRoundTripper struct {
	callbackID string
}

func (rt hostCallbackRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return hostHTTPDo(rt.callbackID, req)
}
