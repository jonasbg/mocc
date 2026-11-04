package server

import (
	"net/http/httptest"
	"strings"
	"testing"

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
