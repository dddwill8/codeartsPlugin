package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFileNameForEmptyUserIDUsesAccessKey(t *testing.T) {
	a := FileNameFor(Credential{UserID: "", AccessKeyID: "AKID-a"})
	b := FileNameFor(Credential{UserID: "  ", AccessKeyID: "AKID-b"})
	if a != "codearts-AKID-a.json" || b != "codearts-AKID-b.json" {
		t.Fatalf("access key names = %q %q", a, b)
	}
	if a == "codearts-unknown.json" || b == "codearts-unknown.json" {
		t.Fatal("distinct accounts collapsed to codearts-unknown.json")
	}
	if strings.Contains(a, "ak:") || strings.Contains(b, "ak:") {
		t.Fatalf("access key must not be prefixed: %q %q", a, b)
	}
	if got := FileNameFor(Credential{UserID: "u1", AccessKeyID: "AKID-a"}); got != "codearts-u1.json" {
		t.Fatalf("user id should win: %q", got)
	}
	if got := FileNameFor(Credential{UserID: " usr/id "}); got != "codearts-usr_id.json" {
		t.Fatalf("trimmed user id with slash = %q", got)
	}
	if got := FileNameFor(Credential{AccessKeyID: " AK/ID "}); got != "codearts-AK_ID.json" {
		t.Fatalf("trimmed access key with slash = %q", got)
	}
	if got := FileNameFor(Credential{}); got != "codearts-unknown.json" {
		t.Fatalf("both empty = %q", got)
	}
}

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

func TestLooksLikeCodeArts(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
		file string
		want bool
	}{
		{name: "nil body", raw: nil, want: false},
		{name: "empty body", raw: []byte{}, want: false},
		{name: "invalid json", raw: []byte(`{`), want: false},
		{name: "json null", raw: []byte(`null`), want: false},
		{name: "no keys", raw: []byte(`{}`), want: false},
		{name: "empty type", raw: []byte(`{"type":""}`), want: false},
		{name: "null type", raw: []byte(`{"type":null}`), want: false},
		{name: "missing type with keys", raw: []byte(`{"access_key_id":"AK","secret_access_key":"SK"}`), want: false},
		{name: "explicit codearts no keys", raw: []byte(`{"type":"codearts"}`), want: true},
		{name: "explicit CodeArts", raw: []byte(`{"type":"CodeArts"}`), want: true},
		{name: "explicit CODEARTS", raw: []byte(`{"type":"CODEARTS"}`), want: true},
		{name: "other type", raw: []byte(`{"type":"other"}`), want: false},
		{name: "filename other type", raw: []byte(`{"type":"other","access_key_id":"AK"}`), file: "codearts-ak.json", want: true},
		{name: "filename empty type no secret", raw: []byte(`{"type":"","access_key_id":"AK"}`), file: "codearts-ak.json", want: true},
		{name: "filename missing type", raw: []byte(`{"access_key_id":"AK"}`), file: "CODEARTS-User.JSON", want: true},
		{name: "filename without ak", raw: []byte(`{"type":""}`), file: "codearts-ak.json", want: false},
		{name: "filename empty ak", raw: []byte(`{"access_key_id":""}`), file: "codearts-ak.json", want: false},
		{name: "other file no type", raw: []byte(`{"access_key_id":"AK"}`), file: "other.json", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := LooksLikeCodeArts(tc.raw, tc.file); got != tc.want {
				t.Fatalf("LooksLikeCodeArts(%s, %q) = %v, want %v", tc.raw, tc.file, got, tc.want)
			}
		})
	}
}

func TestUpdatedAtIsRFC3339String(t *testing.T) {
	raw, err := MarshalCredential(Credential{AccessKeyID: "AK", SecretAccessKey: "sk", SecurityToken: "st", RefreshToken: "rt"})
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	got, ok := obj["updated_at"].(string)
	if !ok {
		t.Fatalf("updated_at = %#v, want RFC3339 string", obj["updated_at"])
	}
	if _, err := time.Parse(time.RFC3339Nano, got); err != nil {
		t.Fatalf("updated_at %q: %v", got, err)
	}

	old := []byte(`{"type":"codearts","access_key_id":"AK","secret_access_key":"sk","security_token":"st","refresh_token":"rt","updated_at":1793264380}`)
	parsed, err := ParseCredential(old)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.UpdatedAt.IsZero() {
		t.Fatal("unix updated_at did not parse")
	}
	rewritten, err := MarshalCredential(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rewritten), "1793264380") {
		t.Fatalf("unix timestamp kept: %s", rewritten)
	}
}
