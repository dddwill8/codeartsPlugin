package dispatch

import (
	"encoding/json"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestAuthParse(t *testing.T) {
	resetForTest(t)

	cases := []struct {
		name    string
		raw     string
		file    string
		handled bool
	}{
		{name: "empty object", raw: `{}`, handled: false},
		{name: "empty type", raw: `{"type":""}`, handled: false},
		{name: "explicit codearts", raw: `{"type":"codearts"}`, handled: true},
		{name: "codearts filename other type", raw: `{"access_key_id":"AK","type":"other"}`, file: "codearts-ak.json", handled: true},
		{name: "other file no type", raw: `{"access_key_id":"AK"}`, file: "other.json", handled: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := json.Marshal(pluginapi.AuthParseRequest{
				RawJSON:  []byte(tc.raw),
				FileName: tc.file,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := authParseHandled(t, req); got != tc.handled {
				t.Fatalf("Handled = %v, want %v", got, tc.handled)
			}
		})
	}

	t.Run("request with no keys", func(t *testing.T) {
		if authParseHandled(t, []byte(`{}`)) {
			t.Fatal("Handled = true, want false")
		}
	})
}

func authParseHandled(t *testing.T, request []byte) bool {
	t.Helper()
	raw, err := Handle(pluginabi.MethodAuthParse, request)
	if err != nil {
		t.Fatalf("auth.parse: %v", err)
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope: %v\n%s", err, raw)
	}
	if !env.OK {
		msg := ""
		if env.Error != nil {
			msg = env.Error.Code + ": " + env.Error.Message
		}
		t.Fatalf("auth.parse not ok: %s\n%s", msg, raw)
	}
	var resp pluginapi.AuthParseResponse
	if err := json.Unmarshal(env.Result, &resp); err != nil {
		t.Fatalf("decode result: %v\n%s", err, env.Result)
	}
	return resp.Handled
}
