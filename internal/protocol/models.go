package protocol

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// ModelInfo is a discovered model.
type ModelInfo struct {
	ID            string `json:"id"`
	Name          string `json:"name,omitempty"`
	ContextWindow int64  `json:"contextWindow,omitempty"`
	MaxTokens     int64  `json:"maxTokens,omitempty"`
	Benefit       bool   `json:"benefit,omitempty"`
	Desc          string `json:"desc,omitempty"`
}

type accountCatalog struct {
	infos       []ModelInfo
	benefit     map[string]bool
	knows       map[string]bool
	lastBenefit map[string]ModelInfo
	fetched     time.Time
}

var catalog = struct {
	sync.RWMutex
	accounts map[string]*accountCatalog
	known    map[string]string
}{
	accounts: map[string]*accountCatalog{},
	known:    map[string]string{},
}

// SetAccountModels replaces one account's catalog.
func SetAccountModels(accountID string, infos []ModelInfo) {
	setAccountModels(accountID, infos, false)
}

func setAccountModels(accountID string, infos []ModelInfo, keepBenefit bool) {
	if accountID == "" {
		return
	}
	ac := &accountCatalog{
		infos:       append([]ModelInfo(nil), infos...),
		benefit:     make(map[string]bool),
		knows:       make(map[string]bool),
		lastBenefit: map[string]ModelInfo{},
		fetched:     time.Now(),
	}
	catalog.Lock()
	defer catalog.Unlock()
	if catalog.known == nil {
		catalog.known = map[string]string{}
	}
	if prev := catalog.accounts[accountID]; prev != nil {
		for k, v := range prev.lastBenefit {
			ac.lastBenefit[k] = v
		}
	}
	for _, mi := range ac.infos {
		if mi.ID == "" {
			continue
		}
		key := strings.ToLower(mi.ID)
		ac.knows[key] = true
		if mi.Benefit {
			ac.benefit[key] = true
			ac.lastBenefit[key] = mi
		}
		if _, ok := catalog.known[key]; !ok || mi.ID != key {
			catalog.known[key] = mi.ID
		}
	}
	if keepBenefit {
		for key, mi := range ac.lastBenefit {
			if ac.knows[key] {
				continue
			}
			ac.benefit[key] = true
			ac.knows[key] = true
			ac.infos = append(ac.infos, mi)
			if _, ok := catalog.known[key]; !ok || mi.ID != key {
				catalog.known[key] = mi.ID
			}
		}
	}
	catalog.accounts[accountID] = ac
}

// AccountModels returns a copy of one account catalog.
func AccountModels(accountID string) ([]ModelInfo, bool) {
	catalog.RLock()
	defer catalog.RUnlock()
	ac, ok := catalog.accounts[accountID]
	if !ok {
		return nil, false
	}
	return append([]ModelInfo(nil), ac.infos...), true
}

// IsBenefitModel reports whether this account+model must send maas_type=benefit.
func IsBenefitModel(accountID, model string) bool {
	key := strings.ToLower(strings.TrimSpace(model))
	if key == "" {
		return false
	}
	catalog.RLock()
	defer catalog.RUnlock()
	if ac, ok := catalog.accounts[accountID]; ok {
		if ac.benefit[key] {
			return true
		}
		if ac.knows[key] {
			return false
		}
	}
	return false
}

// ModelMaxTokens is the discovered maximum output for this account and model.
// Zero means the catalog has no limit, so the caller must omit max_tokens.
func ModelMaxTokens(accountID, model string) int64 {
	key := strings.ToLower(strings.TrimSpace(model))
	if key == "" {
		return 0
	}
	catalog.RLock()
	defer catalog.RUnlock()
	ac, ok := catalog.accounts[accountID]
	if !ok {
		return 0
	}
	for _, mi := range ac.infos {
		if strings.EqualFold(mi.ID, model) && mi.MaxTokens > 0 {
			return mi.MaxTokens
		}
	}
	return 0
}

// StripModelPrefix returns the Huawei model id for a CPA route name.
// CPA namespaces an auth's models as "<prefix>/<id>" when the auth file sets
// prefix. Huawei only accepts the bare id, so a leading "<prefix>/" is
// removed. When prefix is unknown, a single leading "<seg>/" is still removed:
// Huawei ids themselves never contain "/", and the in-process catalog is empty
// until model.for_auth has run. A name with more than one slash is left as-is.
func StripModelPrefix(model, prefix string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return model
	}
	if p := strings.Trim(strings.TrimSpace(prefix), "/"); p != "" {
		if rest, ok := strings.CutPrefix(model, p+"/"); ok && rest != "" {
			return rest
		}
	}
	rest, ok := singlePrefixRest(model)
	if !ok {
		return model
	}
	return rest
}

// singlePrefixRest returns the part after one leading "<seg>/".
func singlePrefixRest(model string) (string, bool) {
	_, rest, ok := strings.Cut(model, "/")
	if !ok || rest == "" || strings.Contains(rest, "/") {
		return "", false
	}
	return rest, true
}

// CanonicalModel maps case variants to the ID last seen in discovery.
func CanonicalModel(id string) string {
	key := strings.ToLower(strings.TrimSpace(id))
	if key == "" {
		return id
	}
	catalog.RLock()
	exact, ok := catalog.known[key]
	catalog.RUnlock()
	if ok {
		return exact
	}
	return id
}

// MergeModels de-duplicates by lower(id); benefit is OR-ed.
func MergeModels(sets ...[]ModelInfo) []ModelInfo {
	merged := map[string]ModelInfo{}
	for _, set := range sets {
		for _, mi := range set {
			if mi.ID == "" {
				continue
			}
			key := strings.ToLower(mi.ID)
			cur, ok := merged[key]
			if !ok {
				merged[key] = mi
				continue
			}
			benefit := cur.Benefit || mi.Benefit
			keep, drop := cur, mi
			if (mi.ContextWindow > 0) != (cur.ContextWindow > 0) {
				if mi.ContextWindow > 0 {
					keep, drop = mi, cur
				}
			} else if mi.ID != strings.ToLower(mi.ID) && cur.ID == strings.ToLower(cur.ID) {
				keep, drop = mi, cur
			}
			keep.Benefit = benefit
			if keep.Name == "" {
				keep.Name = drop.Name
			}
			if keep.ContextWindow == 0 {
				keep.ContextWindow = drop.ContextWindow
			}
			if keep.MaxTokens == 0 {
				keep.MaxTokens = drop.MaxTokens
			}
			if keep.Desc == "" {
				keep.Desc = drop.Desc
			}
			merged[key] = keep
		}
	}
	out := make([]ModelInfo, 0, len(merged))
	for _, mi := range merged {
		out = append(out, mi)
	}
	sort.Slice(out, func(i, j int) bool {
		li, lj := strings.ToLower(out[i].ID), strings.ToLower(out[j].ID)
		if li != lj {
			return li < lj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// DiscoverModels fetches agent-center + builtin + benefit catalogs.
// Failures on individual sources are ignored; an empty merge stays empty.
func DiscoverModels(client *http.Client, cred SignCredential, accountID string, snapBase, benefitBase string, claimBenefit bool) []ModelInfo {
	if snapBase == "" {
		snapBase = SnapEngineAPIHost
	}
	if benefitBase == "" {
		benefitBase = BenefitHost
	}
	var sets [][]ModelInfo
	if infos, err := fetchAgentModels(client, cred, snapBase); err == nil && len(infos) > 0 {
		sets = append(sets, infos)
	}
	builtinOK := false
	if infos, err := fetchBuiltinModels(client, cred, snapBase); err == nil {
		builtinOK = true
		sets = append(sets, infos)
	}
	benefitOK := false
	if claimBenefit {
		_ = claimBenefitOnce(client, cred, benefitBase)
	}
	if infos, err := fetchBenefitModels(client, cred, benefitBase); err == nil {
		benefitOK = true
		sets = append(sets, infos)
	}
	out := MergeModels(sets...)
	if len(out) == 0 {
		return out
	}
	if accountID != "" {
		setAccountModels(accountID, out, builtinOK && !benefitOK)
	}
	return out
}

func fetchAgentModels(client *http.Client, cred SignCredential, snapBase string) ([]ModelInfo, error) {
	agentID, err := defaultAgentID(client, cred, snapBase)
	if err != nil || agentID == "" {
		return nil, err
	}
	raw, err := getSigned(client, snapBase+EpAgentDetail+"?agent_id="+url.QueryEscape(agentID), cred, map[string]string{
		"Agent-Type": "AgentCenter",
		"X-Language": "zh-cn",
		"Accept":     "application/json",
	})
	if err != nil {
		return nil, err
	}
	var detail struct {
		Gpts struct {
			Models []struct {
				ModelAlias string `json:"model_alias"`
				ModelName  string `json:"model_name"`
				ModelID    string `json:"model_id"`
				Params     struct {
					ContextWindow int64  `json:"context_window"`
					MaxTokens     int64  `json:"max_tokens"`
					ModelID       string `json:"model_id"`
					ModelDesc     string `json:"model_desc"`
				} `json:"model_parameters"`
			} `json:"models"`
		} `json:"gpts"`
	}
	if err := json.Unmarshal(raw, &detail); err != nil {
		return nil, err
	}
	out := make([]ModelInfo, 0, len(detail.Gpts.Models))
	for _, m := range detail.Gpts.Models {
		// model_name is the display label (DeepSeek-V4.1-Flash-1017). InferHub
		// registers model_parameters.model_id (deepseek-v4.1-flash) and rejects
		// the label as InferHub.001001005.400.
		id := firstNonEmpty(m.Params.ModelID, m.ModelID, m.ModelName, m.ModelAlias)
		if id == "" {
			continue
		}
		out = append(out, ModelInfo{
			ID: id, Name: id,
			ContextWindow: m.Params.ContextWindow,
			MaxTokens:     m.Params.MaxTokens,
			Desc:          m.Params.ModelDesc,
		})
	}
	return out, nil
}

func defaultAgentID(client *http.Client, cred SignCredential, snapBase string) (string, error) {
	raw, err := getSigned(client, snapBase+EpAgentList+"?offset=0&limit=100&is_primary_agent=true", cred, map[string]string{
		"Agent-Type": "AgentCenter",
		"X-Language": "zh-cn",
		"Accept":     "application/json",
	})
	if err != nil {
		return "", err
	}
	var out struct {
		Agents []struct {
			AgentID   string `json:"agent_id"`
			AgentName string `json:"agent_name"`
			Primary   bool   `json:"is_primary_agent"`
			ShowInIDE bool   `json:"show_in_ide"`
			Alias     struct {
				ZhCN string `json:"alias_zh_cn"`
			} `json:"alias"`
		} `json:"agents"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	for _, a := range out.Agents {
		if a.AgentName == "CodeAgent" && a.Alias.ZhCN == "智能体" && a.ShowInIDE {
			return a.AgentID, nil
		}
	}
	for _, a := range out.Agents {
		if a.Primary {
			return a.AgentID, nil
		}
	}
	if len(out.Agents) > 0 {
		return out.Agents[0].AgentID, nil
	}
	return "", nil
}

func fetchBuiltinModels(client *http.Client, cred SignCredential, snapBase string) ([]ModelInfo, error) {
	raw, err := getSigned(client, snapBase+EpModelBuiltin, cred, map[string]string{
		"Content-Type": "application/json",
		"Agent-Type":   "PromptCenter",
		"X-Language":   "zh-cn",
	})
	if err != nil {
		return nil, err
	}
	var out struct {
		BuiltinModels []struct {
			ModelID       string `json:"model_id"`
			ModelName     string `json:"model_name"`
			ModelDesc     string `json:"model_desc"`
			ContextWindow int64  `json:"context_window"`
			MaxTokens     int64  `json:"max_tokens"`
		} `json:"builtinModels"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	infos := make([]ModelInfo, 0, len(out.BuiltinModels))
	for _, m := range out.BuiltinModels {
		id := firstNonEmpty(m.ModelID, m.ModelName)
		if id == "" {
			continue
		}
		infos = append(infos, ModelInfo{ID: id, Name: id, ContextWindow: m.ContextWindow, MaxTokens: m.MaxTokens, Desc: m.ModelDesc})
	}
	return infos, nil
}

func claimBenefitOnce(client *http.Client, cred SignCredential, benefitBase string) error {
	body := []byte(`{}`)
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(benefitBase, "/")+EpBenefitClaim, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Language", "zh-cn")
	SignRequest(req, body, cred, SignOptions{})
	status, _, err := DoJSON(client, req, 1<<20)
	if err != nil {
		return err
	}
	if status >= 400 {
		return errStatus(status)
	}
	return nil
}

func fetchBenefitModels(client *http.Client, cred SignCredential, benefitBase string) ([]ModelInfo, error) {
	raw, err := getSigned(client, strings.TrimRight(benefitBase, "/")+EpBenefitConfig, cred, map[string]string{
		"Content-Type": "application/json",
		"X-Language":   "zh-cn",
	})
	if err != nil {
		return nil, err
	}
	var out struct {
		ErrorCode string `json:"error_code"`
		Result    struct {
			Models []struct {
				ModelID       string `json:"model_id"`
				ModelName     string `json:"model_name"`
				ModelDesc     string `json:"model_desc"`
				ContextWindow int64  `json:"context_window"`
				MaxTokens     int64  `json:"max_tokens"`
			} `json:"models"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	if out.ErrorCode != "" && out.ErrorCode != "0000" {
		return nil, errStatus(400)
	}
	infos := make([]ModelInfo, 0, len(out.Result.Models))
	for _, m := range out.Result.Models {
		id := firstNonEmpty(m.ModelID, m.ModelName)
		if id == "" {
			continue
		}
		infos = append(infos, ModelInfo{
			ID: id, Name: id,
			ContextWindow: m.ContextWindow, MaxTokens: m.MaxTokens, Desc: m.ModelDesc,
			Benefit: true,
		})
	}
	return infos, nil
}

func getSigned(client *http.Client, rawURL string, cred SignCredential, extra map[string]string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	SignRequest(req, []byte{}, cred, SignOptions{})
	status, body, err := DoJSON(client, req, 4<<20)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, errStatus(status)
	}
	return body, nil
}

type statusError int

func (e statusError) Error() string { return http.StatusText(int(e)) }

func errStatus(code int) error { return statusError(code) }

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
