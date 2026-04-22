package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"mocc/internal/moccconfig"
	"mocc/internal/oidc"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	config := moccconfig.Config{
		Users: []moccconfig.User{
			{Name: "Alice Admin", Email: "alice.admin@test.local", Claims: map[string]interface{}{
				"roles":  []interface{}{"admin"},
				"tenant": "acme",
			}},
			{Name: "Bob Viewer", Email: "bob.viewer@test.local"},
		},
	}
	return New(config, oidc.GenerateKeySet())
}

func TestSkillsIndex(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/.well-known/agent-skills/index.json", nil)
	req.Host = "mocc.test:9999"
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var index struct {
		Version string `json:"version"`
		Skills  []struct {
			Name string `json:"name"`
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"skills"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &index); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(index.Skills) != 1 || index.Skills[0].Name != "mocc-auth" {
		t.Fatalf("unexpected skill entry: %+v", index.Skills)
	}
	if want := "http://mocc.test:9999/.well-known/agent-skills/mocc-auth/SKILL.md"; index.Skills[0].URL != want {
		t.Fatalf("url = %q, want %q", index.Skills[0].URL, want)
	}
}

func TestSkillMd_ContainsLiveUsers(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/.well-known/agent-skills/mocc-auth/SKILL.md", nil)
	req.Host = "mocc.test:9999"
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Fatalf("content-type = %q, want text/markdown*", ct)
	}
	body := w.Body.String()
	for _, want := range []string{
		"alice.admin@test.local",
		"bob.viewer@test.local",
		"Alice Admin",
		"http://mocc.test:9999",
		`"tenant":"acme"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestSkillMd_HonorsForwardedHeaders(t *testing.T) {
	s := newTestServer(t)
	req := httptest.NewRequest("GET", "/.well-known/agent-skills/mocc-auth/SKILL.md", nil)
	req.Host = "internal:9999"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "mocc.example.com")
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "https://mocc.example.com") {
		t.Errorf("body should contain forwarded origin; got first 200 chars: %q", body[:min(200, len(body))])
	}
	if strings.Contains(body, "http://internal:9999") {
		t.Errorf("body should not contain internal origin when forwarded headers are set")
	}
}

func TestSkillRedirects(t *testing.T) {
	s := newTestServer(t)
	paths := []string{"/SKILL.md", "/skill.md", "/skill", "/skills", "/skills.md"}
	want := "/.well-known/agent-skills/mocc-auth/SKILL.md"
	for _, p := range paths {
		req := httptest.NewRequest("GET", p, nil)
		w := httptest.NewRecorder()
		s.Engine.ServeHTTP(w, req)
		if w.Code != http.StatusFound {
			t.Errorf("%s: status %d, want 302", p, w.Code)
			continue
		}
		if loc := w.Header().Get("Location"); loc != want {
			t.Errorf("%s: Location = %q, want %q", p, loc, want)
		}
	}
}

func TestAgentDiscoveryLinkHeader(t *testing.T) {
	s := newTestServer(t)
	// Hit a couple of unrelated endpoints to prove the middleware is global.
	for _, path := range []string{"/jwks.json", "/.well-known/openid-configuration"} {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		s.Engine.ServeHTTP(w, req)
		got := w.Header().Get("Link")
		want := `</.well-known/agent-skills/index.json>; rel="agent-skills"`
		if got != want {
			t.Errorf("%s: Link = %q, want %q", path, got, want)
		}
	}
}

// captureLog redirects log.Default output to a buffer for the duration of the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

// runAuthorizeCodeFlow performs GET+POST /authorize and returns the issued code.
// codeChallenge may be empty to exercise the non-PKCE path.
func runAuthorizeCodeFlow(t *testing.T, s *Server, clientID, redirectURI, codeChallenge string) string {
	t.Helper()
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirectURI)
	if codeChallenge != "" {
		v.Set("code_challenge", codeChallenge)
		v.Set("code_challenge_method", "S256")
	}
	req := httptest.NewRequest("GET", "/authorize?"+v.Encode(), nil)
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET /authorize = %d", w.Code)
	}

	form := url.Values{}
	form.Set("sub", s.Users[0].Email)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", redirectURI)
	if codeChallenge != "" {
		form.Set("code_challenge", codeChallenge)
		form.Set("code_challenge_method", "S256")
	}
	req = httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 302 {
		body, _ := io.ReadAll(w.Body)
		t.Fatalf("POST /authorize = %d: %s", w.Code, string(body))
	}
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("bad redirect: %v", err)
	}
	return u.Query().Get("code")
}

func TestToken_RedirectURIMismatch_WarnsButSucceeds(t *testing.T) {
	s := newTestServer(t)
	logs := captureLog(t)

	clientID := "test-client"
	redirectURI := "http://localhost/cb"
	code := runAuthorizeCodeFlow(t, s, clientID, redirectURI, "")

	// Exchange with a DIFFERENT redirect_uri — a real provider would reject.
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", "http://attacker/cb")
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected forgiving accept; got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(logs.String(), "[warn]") || !strings.Contains(logs.String(), "redirect_uri") {
		t.Errorf("expected warn log about redirect_uri; got:\n%s", logs.String())
	}
}

func TestToken_VerifierWithoutChallenge_WarnsButSucceeds(t *testing.T) {
	s := newTestServer(t)
	logs := captureLog(t)

	clientID := "test-client"
	redirectURI := "http://localhost/cb"
	// Issue a code WITHOUT a challenge.
	code := runAuthorizeCodeFlow(t, s, clientID, redirectURI, "")

	// Now send a verifier anyway.
	verifier := "stray-verifier"
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected forgiving accept; got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(logs.String(), "[warn]") || !strings.Contains(logs.String(), "code_verifier") {
		t.Errorf("expected warn log about code_verifier; got:\n%s", logs.String())
	}
}

// Matching redirect_uri + PKCE should proceed silently (no warn).
func TestToken_RedirectURIMatch_NoWarn(t *testing.T) {
	s := newTestServer(t)
	logs := captureLog(t)

	clientID := "test-client"
	redirectURI := "http://localhost/cb"
	verifier := "the-verifier"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	code := runAuthorizeCodeFlow(t, s, clientID, redirectURI, challenge)

	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("token failed: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(logs.String(), "[warn]") {
		t.Errorf("unexpected warn on happy path:\n%s", logs.String())
	}
}
