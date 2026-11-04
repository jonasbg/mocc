package server

import (
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"mocc/internal/moccconfig"
	"mocc/internal/oidc"

	"github.com/golang-jwt/jwt/v5"
)

func newHardeningServer(t *testing.T) (*Server, []moccconfig.User) {
	t.Helper()
	users := []moccconfig.User{{Name: "Alice", Email: "alice@example.com"}}
	return New(moccconfig.Config{Users: users}, oidc.GenerateKeySet()), users
}

func TestStaticRejectsPathTraversal(t *testing.T) {
	// The on-disk dev fallback resolves relative to the working directory;
	// run from the repo root, where internal/templates/assets/static exists,
	// so a missing traversal guard would actually read files.
	t.Chdir("../..")
	s, _ := newHardeningServer(t)

	for _, p := range []string{
		"/static/../../../../go.mod",
		"/static/%2e%2e/%2e%2e/%2e%2e/%2e%2e/go.mod",
		"/static/../../../../../../../../../../etc/passwd",
		"/static//styles.css",
	} {
		req := httptest.NewRequest("GET", p, nil)
		w := httptest.NewRecorder()
		s.Engine.ServeHTTP(w, req)
		if w.Code != 404 {
			t.Fatalf("%s: expected 404, got %d (body starts %q)", p, w.Code, strings.SplitN(w.Body.String(), "\n", 2)[0])
		}
	}

	// Sanity: a legitimate asset is still served.
	req := httptest.NewRequest("GET", "/static/styles.css", nil)
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 for /static/styles.css, got %d", w.Code)
	}
}

func TestAuthorizePostEvictsExpiredCodes(t *testing.T) {
	s, users := newHardeningServer(t)

	s.authMux.Lock()
	s.authCodes["expired"] = authCodeData{User: users[0], ClientID: "c", ExpiresAt: time.Now().Add(-time.Minute)}
	s.authCodes["live"] = authCodeData{User: users[0], ClientID: "c", ExpiresAt: time.Now().Add(time.Minute)}
	s.authMux.Unlock()

	code := doAuthorize(t, s.Engine, users, "c", "http://localhost/cb", "", "", "")
	if code == "" {
		t.Fatal("expected a code from /authorize")
	}

	s.authMux.Lock()
	defer s.authMux.Unlock()
	if _, ok := s.authCodes["expired"]; ok {
		t.Fatal("expired code was not evicted")
	}
	if _, ok := s.authCodes["live"]; !ok {
		t.Fatal("live code was wrongly evicted")
	}
	if _, ok := s.authCodes[code]; !ok {
		t.Fatal("freshly minted code missing")
	}
}

func TestAuthorizePostInvalidRedirectDoesNotStoreCode(t *testing.T) {
	s, users := newHardeningServer(t)

	form := url.Values{}
	form.Set("sub", users[0].Email)
	form.Set("client_id", "c")
	form.Set("redirect_uri", "http://[::1") // unparseable
	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	s.authMux.Lock()
	defer s.authMux.Unlock()
	if len(s.authCodes) != 0 {
		t.Fatalf("expected no stored codes for invalid redirect_uri, got %d", len(s.authCodes))
	}
}

func TestTokenExpiredCodeIsRemoved(t *testing.T) {
	s, users := newHardeningServer(t)
	s.authMux.Lock()
	s.authCodes["old"] = authCodeData{User: users[0], ClientID: "c", ExpiresAt: time.Now().Add(-time.Second)}
	s.authMux.Unlock()

	if w := doToken(t, s.Engine, "old", "c", ""); w.Code != 400 {
		t.Fatalf("expected 400 for expired code, got %d", w.Code)
	}
	s.authMux.Lock()
	defer s.authMux.Unlock()
	if _, ok := s.authCodes["old"]; ok {
		t.Fatal("expired code should be deleted on failed redemption")
	}
}

func TestTokenAcceptsClientIDFromBasicAuth(t *testing.T) {
	s, users := newHardeningServer(t)
	code := doAuthorize(t, s.Engine, users, "basic-client", "http://localhost/cb", "", "", "")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("basic-client", "whatever")
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 with client_secret_basic, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	claims := decodeClaims(t, resp["id_token"].(string))
	if claims["aud"] != "basic-client" {
		t.Fatalf("expected aud=basic-client, got %v", claims["aud"])
	}

	// Wrong client in Basic auth must still be rejected.
	code = doAuthorize(t, s.Engine, users, "basic-client", "http://localhost/cb", "", "", "")
	req = httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	form.Set("code", code)
	req = httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("other-client", "whatever")
	w = httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for mismatched Basic client_id, got %d", w.Code)
	}
}

func TestTokenExpiresInIsNumeric(t *testing.T) {
	s, users := newHardeningServer(t)
	code := doAuthorize(t, s.Engine, users, "c", "http://localhost/cb", "", "", "")
	w := doToken(t, s.Engine, code, "c", "")
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := resp["expires_in"].(float64); !ok {
		t.Fatalf("expires_in must be a JSON number, got %T (%v)", resp["expires_in"], resp["expires_in"])
	}
}

func decodeClaims(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	parser := jwt.NewParser()
	claims := jwt.MapClaims{}
	if _, _, err := parser.ParseUnverified(token, claims); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	return claims
}
