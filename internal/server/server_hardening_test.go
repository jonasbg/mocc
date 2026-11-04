package server

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"mocc/internal/moccconfig"
	"mocc/internal/oidc"
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
