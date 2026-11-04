package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	texttemplate "text/template"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"mocc/internal/moccconfig"
	"mocc/internal/oidc"
	"mocc/internal/templates"
)

type Server struct {
	Engine        *gin.Engine
	Templates     map[string]*template.Template
	SkillTemplate *texttemplate.Template
	Users         []moccconfig.User
	Keys          *oidc.KeySet
	authCodes     map[string]authCodeData
	authMux       sync.Mutex
}

const (
	authCodeTTL = 5 * time.Minute

	skillIndexPath = "/.well-known/agent-skills/index.json"
	skillMDPath    = "/.well-known/agent-skills/mocc-auth/SKILL.md"
)

type authCodeData struct {
	User                moccconfig.User
	ClientID            string
	RedirectURI         string
	ExpiresAt           time.Time
	Nonce               string
	AuthTime            int64
	CodeChallenge       string
	CodeChallengeMethod string
}

func New(config moccconfig.Config, keys *oidc.KeySet) *Server {
	t := templates.LoadTemplates()
	st := templates.LoadSkillTemplate()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	s := &Server{Engine: r, Templates: t, SkillTemplate: st, Users: config.Users, Keys: keys, authCodes: map[string]authCodeData{}}

	s.configureMiddleware(config.ServerConfig.AllowOrigins)
	s.registerRoutes()

	return s
}

func (s *Server) configureMiddleware(allowOrigins []string) {
	s.Engine.Use(gin.Recovery())
	s.Engine.Use(requestLogger())
	s.Engine.Use(CORS(allowOrigins))
	s.Engine.Use(ignoreClientDisconnects())
	s.Engine.Use(agentDiscoveryLinks())
}

func (s *Server) registerRoutes() {
	r := s.Engine

	r.GET("/", s.handleIndex)
	r.GET("/static/*any", s.handleStatic)

	r.GET("/authorize", s.handleAuthorizeGet)
	r.POST("/authorize", s.handleAuthorizePost)
	r.POST("/token", s.handleToken)
	r.GET("/token/:email", s.handleTokenByEmail)
	r.GET("/login", s.handleLoginRedirect)
	r.GET("/jwks.json", s.handleJWKS)
	r.GET("/userinfo", s.handleUserInfo)
	r.GET("/.well-known/openid-configuration", s.handleDiscovery)

	r.GET(skillIndexPath, s.handleSkillsIndex)
	r.GET(skillMDPath, s.handleSkillMd)
	for _, p := range []string{"/SKILL.md", "/skill.md", "/skill", "/skills", "/skills.md"} {
		r.GET(p, s.handleSkillRedirect)
	}
}

func (s *Server) handleLoginRedirect(c *gin.Context) {
	u := url.URL{Path: "/authorize", RawQuery: c.Request.URL.RawQuery}
	c.Redirect(http.StatusFound, u.String())
}

func (s *Server) renderHTML(c *gin.Context, name string, data interface{}) {
	t := s.Templates[name]
	if t == nil {
		c.String(http.StatusInternalServerError, "template not found")
		return
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	if err := t.ExecuteTemplate(c.Writer, "layout.html", data); err != nil {
		log.Printf("template execute %s: %v", name, err)
	}
}

func (s *Server) handleIndex(c *gin.Context) {
	s.renderHTML(c, "index.html", gin.H{"Users": s.Users})
}

type authorizeParams struct {
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// readAuthorizeParams extracts the shared /authorize parameters using the
// provided getter (c.Query for GET, c.PostForm for POST).
func readAuthorizeParams(get func(string) string) authorizeParams {
	return authorizeParams{
		ClientID:            get("client_id"),
		RedirectURI:         get("redirect_uri"),
		State:               get("state"),
		Nonce:               get("nonce"),
		CodeChallenge:       get("code_challenge"),
		CodeChallengeMethod: get("code_challenge_method"),
	}
}

func (s *Server) handleAuthorizeGet(c *gin.Context) {
	p := readAuthorizeParams(c.Query)
	if p.ClientID == "" || p.RedirectURI == "" {
		c.String(400, "Missing client_id or redirect_uri")
		return
	}
	if rt := c.Query("response_type"); rt != "code" {
		log.Printf("[warn] /authorize response_type=%q (expected \"code\") — a real provider would reject this", rt)
	}
	s.renderHTML(c, "login.html", gin.H{
		"Users":               s.Users,
		"ClientID":            p.ClientID,
		"RedirectURI":         p.RedirectURI,
		"State":               p.State,
		"Nonce":               p.Nonce,
		"CodeChallenge":       p.CodeChallenge,
		"CodeChallengeMethod": p.CodeChallengeMethod,
	})
}

func (s *Server) handleAuthorizePost(c *gin.Context) {
	p := readAuthorizeParams(c.PostForm)
	email := c.PostForm("email")
	if email == "" {
		email = c.PostForm("sub") // legacy field name, kept for existing harnesses
	}
	if email == "" || p.ClientID == "" || p.RedirectURI == "" {
		c.String(400, "Missing parameters")
		return
	}
	user := s.findUserByEmail(email)
	if user == nil {
		c.String(400, "Invalid user")
		return
	}
	// Parse redirect_uri before minting the code so a bad URI does not leave
	// an orphaned entry in authCodes that can never be delivered or redeemed.
	u, err := url.Parse(p.RedirectURI)
	if err != nil {
		c.String(400, "Invalid redirect_uri")
		return
	}
	code, err := newAuthCode()
	if err != nil {
		c.String(500, "Failed to generate authorization code")
		return
	}
	now := time.Now()
	s.authMux.Lock()
	for k, v := range s.authCodes {
		if v.ExpiresAt.Before(now) {
			delete(s.authCodes, k)
		}
	}
	s.authCodes[code] = authCodeData{
		User:                *user,
		ClientID:            p.ClientID,
		RedirectURI:         p.RedirectURI,
		ExpiresAt:           now.Add(authCodeTTL),
		Nonce:               p.Nonce,
		AuthTime:            now.Unix(),
		CodeChallenge:       p.CodeChallenge,
		CodeChallengeMethod: p.CodeChallengeMethod,
	}
	s.authMux.Unlock()
	q := u.Query()
	q.Set("code", code)
	if p.State != "" {
		q.Set("state", p.State)
	}
	u.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, u.String())
}

// tokenError writes an RFC 6749 §5.2 JSON error so client libraries can
// surface the `error` code instead of choking on plain text.
func tokenError(c *gin.Context, status int, code, desc string) {
	c.JSON(status, gin.H{"error": code, "error_description": desc})
}

// tokenClientID returns the client_id from the POST form, falling back to
// HTTP Basic auth (client_secret_basic) which many client libraries default to.
func tokenClientID(c *gin.Context) string {
	if id := c.PostForm("client_id"); id != "" {
		return id
	}
	if id, _, ok := c.Request.BasicAuth(); ok {
		if dec, err := url.QueryUnescape(id); err == nil {
			return dec
		}
		return id
	}
	return ""
}

func (s *Server) handleToken(c *gin.Context) {
	code := c.PostForm("code")
	clientID := tokenClientID(c)
	redirectURI := c.PostForm("redirect_uri")
	codeVerifier := c.PostForm("code_verifier")
	s.authMux.Lock()
	auth, ok := s.authCodes[code]
	if !ok || auth.ExpiresAt.Before(time.Now()) {
		if ok {
			// Expired: drop it now rather than waiting for the next /authorize sweep.
			delete(s.authCodes, code)
		}
		s.authMux.Unlock()
		tokenError(c, 400, "invalid_grant", "invalid or expired authorization code")
		return
	}
	delete(s.authCodes, code)
	s.authMux.Unlock()
	// Spec-forgiving checks: real OIDC providers reject these; mocc warns and
	// proceeds so existing test harnesses keep working, but the deviation is
	// visible in logs so bugs surface before hitting a hardened provider.
	if gt := c.PostForm("grant_type"); gt != "authorization_code" {
		log.Printf("[warn] /token grant_type=%q (expected \"authorization_code\") — a real provider would reject this", gt)
	}
	if clientID != auth.ClientID {
		log.Printf("[warn] /token client_id %q does not match /authorize %q — a real provider would reject this", clientID, auth.ClientID)
	}
	if redirectURI != "" && redirectURI != auth.RedirectURI {
		log.Printf("[warn] /token redirect_uri %q does not match /authorize %q — a real provider would reject this", redirectURI, auth.RedirectURI)
	} else if redirectURI == "" && auth.RedirectURI != "" {
		log.Printf("[warn] /token missing redirect_uri — a real provider would reject this (expected %q)", auth.RedirectURI)
	}
	if auth.CodeChallenge == "" && codeVerifier != "" {
		log.Printf("[warn] /token received code_verifier but /authorize had no code_challenge — a real provider would reject this")
	}
	if err := verifyPKCE(auth, codeVerifier); err != nil {
		tokenError(c, 400, "invalid_grant", err.Error())
		return
	}
	claims := tokenClaims(auth.User, s.baseURL(c), auth.ClientID)
	if auth.Nonce != "" {
		claims["nonce"] = auth.Nonce
	}
	if auth.AuthTime > 0 {
		claims["auth_time"] = auth.AuthTime
	}
	token, err := s.Keys.SignIDToken(claims)
	if err != nil {
		tokenError(c, 500, "server_error", "failed to sign token")
		return
	}
	c.JSON(200, gin.H{"access_token": token, "id_token": token, "token_type": "Bearer", "expires_in": 300})
}

func (s *Server) handleTokenByEmail(c *gin.Context) {
	email := c.Param("email")
	if email == "" {
		c.String(400, "Missing email")
		return
	}
	selected := s.findUserByEmail(email)
	if selected == nil {
		c.String(404, "User not found")
		return
	}
	// Optional ?aud=... sets the audience; ID tokens without aud fail strict
	// client validation. A JSON body can still override it via extra claims.
	claims := tokenClaims(*selected, s.baseURL(c), c.Query("aud"))
	if c.Request.Body != nil {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.String(400, "Failed to read body")
			return
		}
		if len(bytes.TrimSpace(body)) > 0 {
			extras := map[string]interface{}{}
			if err := json.Unmarshal(body, &extras); err != nil {
				c.String(400, "Invalid JSON body")
				return
			}
			applyExtraClaims(claims, extras)
		}
	}
	token, err := s.Keys.SignIDToken(claims)
	if err != nil {
		c.String(500, "Failed to sign token")
		return
	}
	c.JSON(200, gin.H{"token": token, "claims": claims})
}

func (s *Server) handleJWKS(c *gin.Context) {
	c.JSON(200, s.Keys.JWKS())
}

// unauthorized writes an RFC 6750 Bearer challenge plus a JSON error body.
func unauthorized(c *gin.Context, desc string) {
	desc = strings.ReplaceAll(truncateDisplay(desc, 120), `"`, `'`)
	c.Header("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+desc+`"`)
	c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": desc})
}

func setIfMissing(m map[string]interface{}, key string, value interface{}) {
	if _, exists := m[key]; !exists {
		m[key] = value
	}
}

func (s *Server) handleUserInfo(c *gin.Context) {
	tokenString, err := extractBearerToken(c.Request)
	if err != nil {
		unauthorized(c, err.Error())
		return
	}

	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return s.Keys.Public, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	if err != nil || !parsedToken.Valid {
		unauthorized(c, fmt.Sprintf("token validation failed: %v", err))
		return
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		unauthorized(c, "unsupported claims type")
		return
	}

	sub := ""
	if rawSub, ok := claims["sub"]; ok {
		sub = fmt.Sprint(rawSub)
	}
	if sub == "" {
		if rawEmail, ok := claims["email"]; ok {
			sub = fmt.Sprint(rawEmail)
		}
	}
	if sub == "" {
		unauthorized(c, "token missing subject claims")
		return
	}

	response := filterUserInfoClaims(claims)
	response["sub"] = sub

	if user := s.findUserBySub(sub); user != nil {
		if user.Email != "" {
			setIfMissing(response, "email", user.Email)
		}
		if user.Name != "" {
			setIfMissing(response, "name", user.Name)
		}
		for k, v := range user.Claims {
			setIfMissing(response, k, v)
		}
	}

	c.JSON(http.StatusOK, response)
}

func (s *Server) handleDiscovery(c *gin.Context) {
	issuer := s.baseURL(c)
	config := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/jwks.json",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "none"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
	}
	c.JSON(200, config)
}

func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		if len(authHeader) > 7 && strings.EqualFold(authHeader[:7], "Bearer ") {
			token := strings.TrimSpace(authHeader[7:])
			if token != "" {
				return token, nil
			}
		}
	}

	if token := r.URL.Query().Get("access_token"); token != "" {
		return token, nil
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			if token := r.PostForm.Get("access_token"); token != "" {
				return token, nil
			}
		}
	}

	return "", errors.New("missing bearer token")
}

func filterUserInfoClaims(claims jwt.MapClaims) map[string]interface{} {
	// "sub" is reserved here because the caller sets it explicitly.
	reserved := map[string]struct{}{
		"iss": {}, "sub": {}, "aud": {}, "iat": {}, "exp": {}, "nbf": {}, "jti": {},
		"azp": {}, "at_hash": {}, "c_hash": {}, "auth_time": {},
	}
	result := make(map[string]interface{})
	for k, v := range claims {
		if _, skip := reserved[k]; skip {
			continue
		}
		result[k] = v
	}
	return result
}

func (s *Server) findUserBySub(sub string) *moccconfig.User {
	for i := range s.Users {
		if s.Users[i].Sub == sub || s.Users[i].Email == sub {
			return &s.Users[i]
		}
	}
	return nil
}

func (s *Server) findUserByEmail(email string) *moccconfig.User {
	for i := range s.Users {
		if s.Users[i].Email == email {
			return &s.Users[i]
		}
	}
	return nil
}
