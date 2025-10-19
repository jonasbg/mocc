package oidc_test

import (
	"encoding/base64"
	"testing"

	"mocc/internal/oidc"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWKSContainsKey(t *testing.T) {
	ks := oidc.GenerateKeySet()
	jwks := ks.JWKS()
	keys, ok := jwks["keys"]
	if !ok {
		t.Fatalf("jwks missing keys field: %#v", jwks)
	}
	arr, ok := keys.([]map[string]interface{})
	if !ok {
		// Try the common encoding where it's []interface{}
		if ia, iok := keys.([]interface{}); iok && len(ia) > 0 {
			if m, mok := ia[0].(map[string]interface{}); mok {
				arr = []map[string]interface{}{m}
			}
		}
	}
	if len(arr) == 0 {
		t.Fatalf("no keys found in jwks: %#v", jwks)
	}
	k := arr[0]
	if kid, ok := k["kid"].(string); !ok || kid == "" {
		t.Fatalf("kid missing or not string: %#v", k)
	} else if kid != ks.KeyID {
		t.Fatalf("kid mismatch: got %s want %s", kid, ks.KeyID)
	}
	if n, ok := k["n"].(string); !ok || n == "" {
		t.Fatalf("n missing or not string: %#v", k)
	} else {
		if _, err := base64.RawURLEncoding.DecodeString(n); err != nil {
			t.Fatalf("n not valid base64url: %v", err)
		}
	}
	if e, ok := k["e"].(string); !ok || e == "" {
		t.Fatalf("e missing or not string: %#v", k)
	} else {
		if _, err := base64.RawURLEncoding.DecodeString(e); err != nil {
			t.Fatalf("e not valid base64url: %v", err)
		}
	}
}
func TestGenerateAndSign(t *testing.T) {
	ks := oidc.GenerateKeySet()
	if ks == nil || ks.Private == nil || ks.Public == nil {
		t.Fatalf("keys not generated")
	}
	claims := jwt.MapClaims{"sub": "alice@example.com"}
	tok, err := ks.SignIDToken(claims)
	if err != nil {
		t.Fatalf("SignIDToken failed: %v", err)
	}
	if tok == "" {
		t.Fatalf("empty token")
	}
}
