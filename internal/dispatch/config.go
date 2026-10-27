package dispatch

import (
	"strconv"
	"strings"
	"sync"

	"github.com/dddwill8/codeartsPlugin/internal/protocol"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// Config is plugin-owned configuration under plugins.configs.codearts.
type Config struct {
	CallbackHost     string
	CallbackPort     int
	CallbackPath     string
	BenefitAutoClaim bool
}

func defaultConfig() Config {
	return Config{
		CallbackHost:     "127.0.0.1",
		CallbackPort:     18080,
		CallbackPath:     "/oauth/callback",
		BenefitAutoClaim: true,
	}
}

var (
	cfgMu   sync.RWMutex
	current = defaultConfig()
)

func currentConfig() Config {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return current
}

func setConfig(c Config) {
	if c.CallbackHost == "" {
		c.CallbackHost = "127.0.0.1"
	}
	if c.CallbackPath == "" {
		c.CallbackPath = "/oauth/callback"
	}
	if !strings.HasPrefix(c.CallbackPath, "/") {
		c.CallbackPath = "/" + c.CallbackPath
	}
	cfgMu.Lock()
	current = c
	cfgMu.Unlock()
}

func parseConfigYAML(raw []byte) Config {
	cfg := defaultConfig()
	if len(raw) == 0 {
		return cfg
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"'`)
		switch key {
		case "oauth_callback_host":
			if val != "" {
				cfg.CallbackHost = val
			}
		case "oauth_callback_port":
			if n, err := strconv.Atoi(val); err == nil {
				cfg.CallbackPort = n
			}
		case "oauth_callback_path":
			if val != "" {
				cfg.CallbackPath = val
			}
		case "benefit_auto_claim":
			cfg.BenefitAutoClaim = val == "true" || val == "yes" || val == "1"
		}
	}
	return cfg
}

func configFields() []pluginapi.ConfigField {
	d := defaultConfig()
	return []pluginapi.ConfigField{
		{
			Name:        "oauth_callback_host",
			Type:        pluginapi.ConfigFieldTypeString,
			Default:     d.CallbackHost,
			Description: "Listen address for Huawei OAuth /oauth/callback (ticket poll still works if the port is unreachable).",
		},
		{
			Name:        "oauth_callback_port",
			Type:        pluginapi.ConfigFieldTypeInteger,
			Default:     d.CallbackPort,
			Description: "Listen port advertised to Huawei as the OAuth callback port (redirect_uri is always http://127.0.0.1:<port>/oauth/callback).",
		},
		{
			Name:        "oauth_callback_path",
			Type:        pluginapi.ConfigFieldTypeString,
			Default:     d.CallbackPath,
			Description: "OAuth callback path.",
		},
		{
			Name:        "benefit_auto_claim",
			Type:        pluginapi.ConfigFieldTypeBoolean,
			Default:     d.BenefitAutoClaim,
			Description: "Claim free-tier (benefit) models during per-auth discovery.",
		},
	}
}

func loginConfig() protocol.LoginConfig {
	cfgMu.RLock()
	path := current.CallbackPath
	cfgMu.RUnlock()
	lc := protocol.DefaultLoginConfig()
	endpointsMu.RLock()
	if endpoints.PortalHost != "" {
		lc.PortalHost = endpoints.PortalHost
	}
	if endpoints.SnapManager != "" {
		lc.SnapManager = endpoints.SnapManager
	}
	if endpoints.STSHost != "" {
		lc.STSHost = endpoints.STSHost
	}
	endpointsMu.RUnlock()
	lc.RedirectPath = path
	return lc
}

type endpointOverride struct {
	PortalHost  string
	SnapManager string
	STSHost     string
	SnapEngine  string
	Benefit     string
}

var (
	endpointsMu sync.RWMutex
	endpoints   endpointOverride
)

// SetEndpoints overrides Huawei base URLs (tests).
func SetEndpoints(e endpointOverride) {
	endpointsMu.Lock()
	endpoints = e
	endpointsMu.Unlock()
}

func snapEngineBase() string {
	endpointsMu.RLock()
	defer endpointsMu.RUnlock()
	if endpoints.SnapEngine != "" {
		return endpoints.SnapEngine
	}
	return protocol.SnapEngineAPIHost
}

func benefitBase() string {
	endpointsMu.RLock()
	defer endpointsMu.RUnlock()
	if endpoints.Benefit != "" {
		return endpoints.Benefit
	}
	return protocol.BenefitHost
}
