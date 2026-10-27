package protocol

import (
	"encoding/json"
	"strings"
	"time"
)

// Credential is the persisted CodeArts OAuth + STS record.
// client_id and dpop_private_key.d must survive refresh; refresh_token is one-time.
type Credential struct {
	Type            string            `json:"type"`
	UserID          string            `json:"user_id,omitempty"`
	UserName        string            `json:"user_name,omitempty"`
	DomainID        string            `json:"domain_id,omitempty"`
	AccessKeyID     string            `json:"access_key_id"`
	SecretAccessKey string            `json:"secret_access_key"`
	SecurityToken   string            `json:"security_token"`
	Expiration      string            `json:"expiration,omitempty"`
	RefreshToken    string            `json:"refresh_token"`
	CodeVerifier    string            `json:"code_verifier,omitempty"`
	ClientID        string            `json:"client_id,omitempty"`
	DPoPPrivateKey  map[string]string `json:"dpop_private_key,omitempty"`
	UpdatedAt       int64             `json:"updated_at,omitempty"`
}

// TokenResponse is the STS / oauth2/tokens JSON body.
type TokenResponse struct {
	UserID       string      `json:"user_id"`
	UserName     string      `json:"user_name"`
	DomainID     string      `json:"domain_id"`
	RefreshToken string      `json:"refresh_token"`
	Credentials  STSCreds    `json:"credentials"`
	Credential   LegacyCreds `json:"credential"`
	Error        string      `json:"error"`
	ErrorCode    string      `json:"error_code"`
	ErrorMessage string      `json:"error_msg"`
}

// STSCreds is the nested credentials object from oauth2/tokens.
type STSCreds struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SecurityToken   string `json:"security_token"`
	Expiration      string `json:"expiration"`
}

// LegacyCreds is the ticket-channel credential object.
type LegacyCreds struct {
	Access        string `json:"access"`
	Secret        string `json:"secret"`
	SecurityToken string `json:"securitytoken"`
	ExpiresAt     string `json:"expires_at"`
}

// Normalize fills credentials from the legacy ticket object when needed.
func (t *TokenResponse) Normalize() {
	if t == nil {
		return
	}
	if t.Credentials.SecurityToken == "" && t.Credential.SecurityToken != "" {
		t.Credentials = STSCreds{
			AccessKeyID:     t.Credential.Access,
			SecretAccessKey: t.Credential.Secret,
			SecurityToken:   t.Credential.SecurityToken,
			Expiration:      t.Credential.ExpiresAt,
		}
	}
}

// HasSTS reports whether the response contains usable STS material.
func (t TokenResponse) HasSTS() bool {
	t.Normalize()
	return t.Credentials.SecurityToken != "" && t.Credentials.AccessKeyID != ""
}

// ParseTokenResponse decodes an oauth2/tokens or ticket JSON body.
func ParseTokenResponse(raw []byte) (TokenResponse, error) {
	var tok TokenResponse
	if err := json.Unmarshal(raw, &tok); err != nil {
		return TokenResponse{}, err
	}
	tok.Normalize()
	return tok, nil
}

// NewCredentialFromToken builds a persistable credential from a token response.
func NewCredentialFromToken(tok TokenResponse, verifier string, clientID string, dpop DPoPPrivateJWK) Credential {
	tok.Normalize()
	if clientID == "" {
		clientID = ClientID
	}
	c := Credential{
		Type:            Provider,
		UserID:          tok.UserID,
		UserName:        tok.UserName,
		DomainID:        tok.DomainID,
		AccessKeyID:     tok.Credentials.AccessKeyID,
		SecretAccessKey: tok.Credentials.SecretAccessKey,
		SecurityToken:   tok.Credentials.SecurityToken,
		Expiration:      tok.Credentials.Expiration,
		RefreshToken:    tok.RefreshToken,
		CodeVerifier:    verifier,
		ClientID:        clientID,
		UpdatedAt:       time.Now().Unix(),
	}
	if len(dpop) > 0 {
		c.DPoPPrivateKey = cloneStringMap(dpop)
	}
	return c
}

// ApplyRefresh copies rotated STS + refresh_token onto prev while keeping
// client_id, code_verifier, and the DPoP private JWK (including d) unchanged.
func ApplyRefresh(prev Credential, tok TokenResponse) Credential {
	tok.Normalize()
	next := prev
	if next.Type == "" {
		next.Type = Provider
	}
	if next.ClientID == "" {
		next.ClientID = ClientID
	}
	if tok.Credentials.AccessKeyID != "" {
		next.AccessKeyID = tok.Credentials.AccessKeyID
	}
	if tok.Credentials.SecretAccessKey != "" {
		next.SecretAccessKey = tok.Credentials.SecretAccessKey
	}
	if tok.Credentials.SecurityToken != "" {
		next.SecurityToken = tok.Credentials.SecurityToken
	}
	if tok.Credentials.Expiration != "" {
		next.Expiration = tok.Credentials.Expiration
	}
	if tok.RefreshToken != "" {
		next.RefreshToken = tok.RefreshToken
	}
	if tok.UserID != "" {
		next.UserID = tok.UserID
	}
	if tok.UserName != "" {
		next.UserName = tok.UserName
	}
	if tok.DomainID != "" {
		next.DomainID = tok.DomainID
	}
	next.UpdatedAt = time.Now().Unix()
	return next
}

// ParseCredential decodes a persisted auth JSON object.
func ParseCredential(raw []byte) (Credential, error) {
	var c Credential
	if len(raw) == 0 {
		return c, nil
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return Credential{}, err
	}
	if c.Type == "" {
		c.Type = Provider
	}
	if c.ClientID == "" {
		c.ClientID = ClientID
	}
	return c, nil
}

// MarshalCredential encodes the credential as JSON.
func MarshalCredential(c Credential) ([]byte, error) {
	if c.Type == "" {
		c.Type = Provider
	}
	if c.ClientID == "" {
		c.ClientID = ClientID
	}
	if c.UpdatedAt == 0 {
		c.UpdatedAt = time.Now().Unix()
	}
	return json.Marshal(c)
}

// LooksLikeCodeArts reports whether raw JSON is a CodeArts auth file.
func LooksLikeCodeArts(raw []byte, fileName string) bool {
	c, err := ParseCredential(raw)
	if err != nil {
		return false
	}
	if strings.EqualFold(c.Type, Provider) {
		return true
	}
	name := strings.ToLower(fileName)
	if strings.HasPrefix(name, "codearts-") && strings.HasSuffix(name, ".json") && c.AccessKeyID != "" {
		return true
	}
	return false
}

// AccountKey is the in-process catalog id for this credential.
// Huawei token responses sometimes omit user_id; fall back to access_key_id
// so benefit flags from model.for_auth still apply at execute time.
func AccountKey(c Credential) string {
	if id := strings.TrimSpace(c.UserID); id != "" {
		return id
	}
	if id := strings.TrimSpace(c.AccessKeyID); id != "" {
		return "ak:" + id
	}
	return "default"
}

// FileNameFor returns the host auth file name for this credential.
func FileNameFor(c Credential) string {
	id := strings.TrimSpace(c.UserID)
	if id == "" {
		id = "unknown"
	}
	id = strings.ReplaceAll(id, "/", "_")
	return "codearts-" + id + ".json"
}

// SignCredentialFrom returns HMAC material.
func SignCredentialFrom(c Credential) SignCredential {
	return SignCredential{
		AccessKeyID:     c.AccessKeyID,
		SecretAccessKey: c.SecretAccessKey,
		SecurityToken:   c.SecurityToken,
	}
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
