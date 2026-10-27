package protocol

import (
	"encoding/json"
	"testing"
)

func TestAccountKeyFallsBackToAccessKeyWhenUserIDEmpty(t *testing.T) {
	if got := AccountKey(Credential{UserID: "u1", AccessKeyID: "AK"}); got != "u1" {
		t.Fatalf("user_id key = %q", got)
	}
	if got := AccountKey(Credential{AccessKeyID: "AKID1"}); got != "ak:AKID1" {
		t.Fatalf("ak fallback = %q", got)
	}
	if got := AccountKey(Credential{}); got != "default" {
		t.Fatalf("empty key = %q", got)
	}
}

func TestEmptyUserIDStillCachesBenefitCatalog(t *testing.T) {
	key := AccountKey(Credential{AccessKeyID: "AKBEN"})
	SetAccountModels(key, []ModelInfo{
		{ID: "GLM-5.3", Benefit: true},
		{ID: "GLM-5.2", Benefit: false},
	})
	if !IsBenefitModel(key, "GLM-5.3") {
		t.Fatal("discovered benefit model missing maas flag")
	}
	if IsBenefitModel(key, "GLM-5.2") {
		t.Fatal("paid model marked benefit")
	}
	if IsBenefitModel("", "GLM-5.3") {
		t.Fatal("empty account id should not see AK catalog")
	}
	if IsBenefitModel("ak:other", "glm-5.3-flash") {
		t.Fatal("undiscovered id should not inherit a static benefit seed")
	}
}

func TestApplyRefreshKeepsClientIDAndDPoPRotatesSTS(t *testing.T) {
	dpop, err := NewDPoPPrivateJWK()
	if err != nil {
		t.Fatal(err)
	}
	prev := Credential{
		Type:            Provider,
		UserID:          "u1",
		UserName:        "alice",
		AccessKeyID:     "AKOLD",
		SecretAccessKey: "skold",
		SecurityToken:   "sts-old",
		Expiration:      "2026-01-01T00:00:00Z",
		RefreshToken:    "rt-old-onetime",
		CodeVerifier:    "verifier-1",
		ClientID:        ClientID,
		DPoPPrivateKey:  map[string]string{"kty": dpop["kty"], "crv": dpop["crv"], "x": dpop["x"], "y": dpop["y"], "d": dpop["d"]},
	}
	raw, err := MarshalCredential(prev)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := ParseCredential(raw)
	if err != nil {
		t.Fatal(err)
	}
	tok := TokenResponse{
		RefreshToken: "rt-new",
		Credentials: STSCreds{
			AccessKeyID:     "AKNEW",
			SecretAccessKey: "sknew",
			SecurityToken:   "sts-new",
			Expiration:      "2026-06-01T00:00:00Z",
		},
	}
	next := ApplyRefresh(loaded, tok)

	if next.ClientID != ClientID {
		t.Fatalf("client_id changed: %q", next.ClientID)
	}
	if next.DPoPPrivateKey["d"] != dpop["d"] {
		t.Fatalf("dpop d changed: %q -> %q", dpop["d"], next.DPoPPrivateKey["d"])
	}
	if next.DPoPPrivateKey["x"] != dpop["x"] || next.DPoPPrivateKey["y"] != dpop["y"] {
		t.Fatalf("dpop public changed")
	}
	if next.CodeVerifier != "verifier-1" {
		t.Fatalf("code_verifier changed")
	}
	if next.RefreshToken != "rt-new" {
		t.Fatalf("refresh_token = %q", next.RefreshToken)
	}
	if next.AccessKeyID != "AKNEW" || next.SecretAccessKey != "sknew" || next.SecurityToken != "sts-new" {
		t.Fatalf("STS not rotated: %+v", next)
	}
	if next.RefreshToken == "rt-old-onetime" {
		t.Fatal("old refresh_token reused")
	}

	round, err := MarshalCredential(next)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(round, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["client_id"] != ClientID {
		t.Fatalf("json client_id = %v", obj["client_id"])
	}
	jwk, _ := obj["dpop_private_key"].(map[string]any)
	if jwk["d"] != dpop["d"] {
		t.Fatalf("json dpop.d = %v", jwk["d"])
	}
	if obj["refresh_token"] != "rt-new" {
		t.Fatalf("json refresh_token = %v", obj["refresh_token"])
	}
}
