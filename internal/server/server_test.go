package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"mocc/internal/config"
	"mocc/internal/oidc"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func TestMain(m *testing.M) {
	// Quiet Gin logs during tests
	gin.SetMode(gin.ReleaseMode)
	os.Exit(m.Run())
}

// helper: perform authorize flow: GET /authorize?client_id=...&redirect_uri=...&code_challenge=... then POST /authorize with selected user
func doAuthorize(t *testing.T, srv http.Handler, users []config.User, clientID, redirectURI, codeChallenge, method string) (code string) {
	t.Helper()
	// GET authorize to get login page (we don't parse it, just ensure 200)
	v := url.Values{}
	v.Set("client_id", clientID)
	v.Set("redirect_uri", redirectURI)
	if codeChallenge != "" {
		v.Set("code_challenge", codeChallenge)
		v.Set("code_challenge_method", method)
	}
	req := httptest.NewRequest("GET", "/authorize?"+v.Encode(), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("GET /authorize returned %d", w.Code)
	}

	// POST authorize - choose the first user from users slice
	form := url.Values{}
	form.Set("sub", users[0].Email)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", redirectURI)
	if codeChallenge != "" {
		form.Set("code_challenge", codeChallenge)
		form.Set("code_challenge_method", method)
	}
	req = httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	// Expect redirect to redirectURI with code param
	if w.Code != 302 {
		t.Fatalf("POST /authorize returned %d, body: %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("invalid redirect location: %v", err)
	}
	return u.Query().Get("code")
}

func doToken(t *testing.T, srv http.Handler, code, clientID, verifier string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", clientID)
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func TestPKCE_S256(t *testing.T) {
	users := []config.User{{Name: "Alice", Email: "alice@example.com"}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	clientID := "test-client"
	redirectURI := "http://localhost/cb"
	verifier := "test-verifier-123"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	code := doAuthorize(t, s.Engine, users, clientID, redirectURI, challenge, "S256")
	if code == "" {
		t.Fatalf("no code returned from authorize")
	}

	w := doToken(t, s.Engine, code, clientID, verifier)
	if w.Code != 200 {
		body, _ := io.ReadAll(w.Body)
		t.Fatalf("token exchange failed: %d %s", w.Code, string(body))
	}
}

func TestPKCE_Plain(t *testing.T) {
	users := []config.User{{Name: "Alice", Email: "alice@example.com"}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	clientID := "test-client"
	redirectURI := "http://localhost/cb"
	verifier := "plain-verifier"
	challenge := verifier

	code := doAuthorize(t, s.Engine, users, clientID, redirectURI, challenge, "plain")
	if code == "" {
		t.Fatalf("no code returned from authorize")
	}

	w := doToken(t, s.Engine, code, clientID, verifier)
	if w.Code != 200 {
		body, _ := io.ReadAll(w.Body)
		t.Fatalf("token exchange failed: %d %s", w.Code, string(body))
	}
}

func TestPKCE_WrongVerifier(t *testing.T) {
	users := []config.User{{Name: "Alice", Email: "alice@example.com"}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	clientID := "test-client"
	redirectURI := "http://localhost/cb"
	verifier := "test-verifier-123"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	code := doAuthorize(t, s.Engine, users, clientID, redirectURI, challenge, "S256")
	if code == "" {
		t.Fatalf("no code returned from authorize")
	}

	w := doToken(t, s.Engine, code, clientID, "wrong-verifier")
	if w.Code == 200 {
		t.Fatalf("expected token exchange to fail with wrong verifier")
	}
}

func TestTokenIncludesUserClaims(t *testing.T) {
	users := []config.User{{
		Name:   "Alice",
		Email:  "alice@example.com",
		Claims: map[string]interface{}{"role": "admin", "profile": map[string]interface{}{"tier": "gold"}},
	}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	clientID := "test-client"
	redirectURI := "http://localhost/cb"
	verifier := "test-verifier-abc"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	code := doAuthorize(t, s.Engine, users, clientID, redirectURI, challenge, "S256")
	if code == "" {
		t.Fatalf("no code returned from authorize")
	}

	w := doToken(t, s.Engine, code, clientID, verifier)
	if w.Code != 200 {
		body, _ := io.ReadAll(w.Body)
		t.Fatalf("token exchange failed: %d %s", w.Code, string(body))
	}

	var resp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.IDToken == "" {
		t.Fatal("expected id_token in response")
	}

	parsed, err := jwt.Parse(resp.IDToken, func(token *jwt.Token) (interface{}, error) {
		return ks.Public, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("unexpected claims type %T", parsed.Claims)
	}
	if claims["role"] != "admin" {
		t.Fatalf("expected role claim 'admin', got %v", claims["role"])
	}
	profileClaim, ok := claims["profile"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected profile claim to be an object, got %T", claims["profile"])
	}
	if profileClaim["tier"] != "gold" {
		t.Fatalf("expected profile.tier 'gold', got %v", profileClaim["tier"])
	}
}

func TestTokenByEmail(t *testing.T) {
	users := []config.User{{
		Name:   "Alice",
		Email:  "alice@example.com",
		Claims: map[string]interface{}{"role": "tester", "profile": map[string]interface{}{"env": "dev"}},
	}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	req := httptest.NewRequest("GET", "/token/alice@example.com", nil)
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var resp struct {
		Token  string                 `json:"token"`
		Claims map[string]interface{} `json:"claims"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected token in response")
	}
	if resp.Claims["email"] != users[0].Email {
		t.Fatalf("expected email claim %q, got %v", users[0].Email, resp.Claims["email"])
	}
	if resp.Claims["role"] != "tester" {
		t.Fatalf("expected role claim 'tester', got %v", resp.Claims["role"])
	}
	profile, ok := resp.Claims["profile"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected profile claim to be an object, got %T", resp.Claims["profile"])
	}
	if profile["env"] != "dev" {
		t.Fatalf("expected profile.env 'dev', got %v", profile["env"])
	}

	parsed, err := jwt.Parse(resp.Token, func(token *jwt.Token) (interface{}, error) {
		return ks.Public, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("expected token to be valid")
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("unexpected claims type %T", parsed.Claims)
	}
	if claims["email"] != users[0].Email {
		t.Fatalf("expected email claim %q, got %v", users[0].Email, claims["email"])
	}
	if claims["role"] != "tester" {
		t.Fatalf("expected role claim 'tester', got %v", claims["role"])
	}
	profileClaim, ok := claims["profile"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected profile claim to be an object, got %T", claims["profile"])
	}
	if profileClaim["env"] != "dev" {
		t.Fatalf("expected profile.env 'dev', got %v", profileClaim["env"])
	}
}

func TestTokenByEmailWithExtras(t *testing.T) {
	users := []config.User{{
		Name:   "Alice",
		Email:  "alice@example.com",
		Claims: map[string]interface{}{"role": "tester", "feature": "baseline"},
	}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	body := bytes.NewBufferString(`{"aud":"my-client","custom":"value"}`)
	req := httptest.NewRequest("GET", "/token/alice@example.com", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}

	var resp struct {
		Token  string                 `json:"token"`
		Claims map[string]interface{} `json:"claims"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Claims["aud"] != "my-client" {
		t.Fatalf("expected aud claim 'my-client', got %v", resp.Claims["aud"])
	}
	if resp.Claims["custom"] != "value" {
		t.Fatalf("expected custom claim 'value', got %v", resp.Claims["custom"])
	}
	if resp.Claims["feature"] != "baseline" {
		t.Fatalf("expected feature claim 'baseline', got %v", resp.Claims["feature"])
	}

	parsed, err := jwt.Parse(resp.Token, func(token *jwt.Token) (interface{}, error) {
		return ks.Public, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("unexpected claims type %T", parsed.Claims)
	}
	if claims["aud"] != "my-client" {
		t.Fatalf("expected aud claim 'my-client', got %v", claims["aud"])
	}
	if claims["custom"] != "value" {
		t.Fatalf("expected custom claim 'value', got %v", claims["custom"])
	}
	if claims["feature"] != "baseline" {
		t.Fatalf("expected feature claim 'baseline', got %v", claims["feature"])
	}
}

func TestTokenByEmailUnknownUser(t *testing.T) {
	users := []config.User{{Name: "Alice", Email: "alice@example.com"}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	req := httptest.NewRequest("GET", "/token/bob@example.com", nil)
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown user, got %d", w.Code)
	}
}

func TestHandleLoginRedirect(t *testing.T) {
	users := []config.User{{Name: "Alice", Email: "alice@example.com"}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	req := httptest.NewRequest("GET", "/login?foo=bar", nil)
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 302 {
		t.Fatalf("expected 302 redirect, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/authorize?") {
		t.Fatalf("expected redirect to /authorize, got %s", loc)
	}
}

func TestHandleIndex(t *testing.T) {
	users := []config.User{{Name: "Alice", Email: "alice@example.com"}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
}

func TestHandleJWKS(t *testing.T) {
	users := []config.User{{Name: "Alice", Email: "alice@example.com"}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	req := httptest.NewRequest("GET", "/jwks.json", nil)
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "\"keys\"") {
		t.Fatalf("expected JWKS JSON in response")
	}
}

func TestHandleDiscovery(t *testing.T) {
	users := []config.User{{Name: "Alice", Email: "alice@example.com"}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "issuer") {
		t.Fatalf("expected issuer in discovery JSON")
	}
}

func TestHandleAuthorizeGet_MissingParams(t *testing.T) {
	users := []config.User{{Name: "Alice", Email: "alice@example.com"}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	req := httptest.NewRequest("GET", "/authorize", nil)
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for missing params, got %d", w.Code)
	}
}

func TestHandleAuthorizePost_MissingParams(t *testing.T) {
	users := []config.User{{Name: "Alice", Email: "alice@example.com"}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	req := httptest.NewRequest("POST", "/authorize", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for missing params, got %d", w.Code)
	}
}

func TestHandleAuthorizePost_InvalidUser(t *testing.T) {
	users := []config.User{{Name: "Alice", Email: "alice@example.com"}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	form := url.Values{}
	form.Set("sub", "notfound@example.com")
	form.Set("client_id", "test-client")
	form.Set("redirect_uri", "http://localhost/cb")
	req := httptest.NewRequest("POST", "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for invalid user, got %d", w.Code)
	}
}

func TestHandleToken_InvalidOrExpiredCode(t *testing.T) {
	users := []config.User{{Name: "Alice", Email: "alice@example.com"}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	form := url.Values{}
	form.Set("code", "badcode")
	form.Set("client_id", "test-client")
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for invalid/expired code, got %d", w.Code)
	}
}

func TestHandleToken_MissingCodeVerifier(t *testing.T) {
	users := []config.User{{Name: "Alice", Email: "alice@example.com"}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	// Create a valid code with PKCE challenge
	code := "testcodepkce"
	s.authMux.Lock()
	s.authCodes[code] = authCodeData{
		User:                users[0],
		ClientID:            "test-client",
		ExpiresAt:           time.Now().Add(5 * time.Minute),
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
	}
	s.authMux.Unlock()

	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", "test-client")
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for missing code_verifier, got %d", w.Code)
	}
}

func TestHandleToken_UnsupportedCodeChallengeMethod(t *testing.T) {
	users := []config.User{{Name: "Alice", Email: "alice@example.com"}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	code := "testcodebadmethod"
	s.authMux.Lock()
	s.authCodes[code] = authCodeData{
		User:                users[0],
		ClientID:            "test-client",
		ExpiresAt:           time.Now().Add(5 * time.Minute),
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "BADMETHOD",
	}
	s.authMux.Unlock()

	form := url.Values{}
	form.Set("code", code)
	form.Set("client_id", "test-client")
	form.Set("code_verifier", "challenge")
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for unsupported code_challenge_method, got %d", w.Code)
	}
}

func TestStaticCSSServed(t *testing.T) {
	users := []config.User{{Name: "Alice", Email: "alice@example.com"}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	req := httptest.NewRequest("GET", "/static/styles.css", nil)
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/css") {
		t.Fatalf("expected Content-Type text/css, got %q", ct)
	}
	if !strings.Contains(w.Body.String(), "font-family") {
		t.Fatalf("expected css body to contain 'font-family', got %q", w.Body.String())
	}
}

func TestIndexTemplateRendering(t *testing.T) {
	users := []config.User{{Name: "Alice Example", Email: "alice@example.com"}}
	ks := oidc.GenerateKeySet()
	s := New(users, ks)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	s.Engine.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
	body := w.Body.String()
	// page title may vary; assert the site name is present
	if !strings.Contains(body, "mocc") {
		t.Fatalf("expected body to contain page title/site name, got %q", body)
	}
	if !strings.Contains(body, "Alice Example") {
		t.Fatalf("expected body to contain user name, got %q", body)
	}
}

func TestRequestLogger(t *testing.T) {
	var buf bytes.Buffer
	origFlags := log.Flags()
	origPrefix := log.Prefix()
	origOutput := log.Writer()
	log.SetFlags(0)
	log.SetPrefix("")
	log.SetOutput(&buf)
	defer func() {
		log.SetFlags(origFlags)
		log.SetPrefix(origPrefix)
		log.SetOutput(origOutput)
	}()

	r := gin.New()
	r.Use(requestLogger())
	r.GET("/authorize", func(c *gin.Context) {
		c.Header("Location", "http://callback")
		c.String(302, "redirecting")
	})

	req := httptest.NewRequest("GET", "/authorize?client_id=test-client&scope=openid", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	out := buf.String()
	if !strings.Contains(out, "GET /authorize -> 302") {
		t.Fatalf("expected log to include method/path/status, got %q", out)
	}
	if !strings.Contains(out, "client_id=test-client") {
		t.Fatalf("expected log to include client_id, got %q", out)
	}
	if !strings.Contains(out, "scope=openid") {
		t.Fatalf("expected log to include scope, got %q", out)
	}
	if !strings.Contains(out, "location=http://callback") {
		t.Fatalf("expected log to include redirect location, got %q", out)
	}
}

func TestIgnoreClientDisconnects(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)

	otherErr := errors.New("boom")
	c.Error(syscall.EPIPE)      // filtered
	c.Error(syscall.ECONNRESET) // filtered
	c.Error(otherErr)           // kept

	mw := ignoreClientDisconnects()
	mw(c)

	if len(c.Errors) != 1 {
		t.Fatalf("expected 1 error left, got %d", len(c.Errors))
	}
	if !errors.Is(c.Errors[0].Err, otherErr) {
		t.Fatalf("expected remaining error to be %v, got %v", otherErr, c.Errors[0].Err)
	}
}

func TestTruncateDisplay(t *testing.T) {
	cases := []struct {
		value string
		limit int
		want  string
	}{
		{"short", 10, "short"},
		{"exact", 5, "exact"},
		{"long-string", 4, "lon…"},
		{"ééééé", 3, "éé…"},
		{"truncate", 1, "t"},
		{"", 5, ""},
	}

	for _, tc := range cases {
		got := truncateDisplay(tc.value, tc.limit)
		if got != tc.want {
			t.Fatalf("truncateDisplay(%q, %d) = %q, want %q", tc.value, tc.limit, got, tc.want)
		}
	}
}
