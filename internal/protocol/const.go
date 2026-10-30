// Package protocol implements the Huawei CodeArts / 码道 cloud protocol:
// PKCE + DPoP OAuth, STS refresh, SDK-HMAC-SHA256 signing, v2 chat, and model catalogs.
package protocol

const (
	PluginID      = "codearts"
	PluginName    = "CodeArts (华为码道)"
	PluginVersion = "0.1.11"
	PluginAuthor  = "codeartsPlugin"

	// Provider is the CPA auth/executor identifier and auth-file type.
	Provider = "codearts"

	SnapEngineAPIHost = "https://snap-access.cn-north-4.myhuaweicloud.com"
	SnapManagerHost   = SnapEngineAPIHost + "/snap-manager"
	PortalHost        = "https://codearts.huaweicloud.com/portal"
	STSHost           = "https://sts.cn-north-4.myhuaweicloud.com"
	BenefitHost       = "https://opengw.developer.huaweicloud.com"

	ClientID = "codearts-agent"

	EpChatV2         = "/api/v2/chat/completions"
	EpAgentList      = "/v1/agent-center/agents/useragents"
	EpAgentDetail    = "/v1/agent-center/agents/detail"
	EpModelBuiltin   = "/v1/model/builtin"
	EpBenefitConfig  = "/api/v1/gateway/config"
	EpBenefitClaim   = "/api/v1/benefit/claim"
	EpLoginTicket    = "/v1/login/ticket"
	EpOAuthTokens    = "/v1/oauth2/tokens"
	EpCurrentUser    = "/v1/current/user"
	EpCallerIdentity = "/v5/caller-identity"

	OAuthPluginName    = "snap_AIIDE"
	OAuthPluginVersion = "5.2.0"

	HeaderMaasType  = "maas_type"
	HeaderModelID   = "model-id"
	HeaderModelName = "model-name"
	MaasBenefit     = "benefit"

	SigningAlgorithm = "SDK-HMAC-SHA256"
	DefaultChatHost  = "snap-access.cn-north-4.myhuaweicloud.com"
)
