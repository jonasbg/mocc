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
	c.Redirect(302, u.String())
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

func (s *Server) handleAuthorizeGet(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	state := c.Query("state")
	nonce := c.Query("nonce")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")
	if clientID == "" || redirectURI == "" {
		c.String(400, "Missing client_id or redirect_uri")
		return
	}
	s.renderHTML(c, "login.html", gin.H{
		"Users":               s.Users,
		"ClientID":            clientID,
		"RedirectURI":         redirectURI,
		"State":               state,
		"Nonce":               nonce,
		"CodeChallenge":       codeChallenge,
		"CodeChallengeMethod": codeChallengeMethod,
	})
}

func (s *Server) handleAuthorizePost(c *gin.Context) {
	sub := c.PostForm("sub")
	clientID := c.PostForm("client_id")
	redirectURI := c.PostForm("redirect_uri")
	state := c.PostForm("state")
	nonce := c.PostForm("nonce")
	codeChallenge := c.PostForm("code_challenge")
	codeChallengeMethod := c.PostForm("code_challenge_method")
	if sub == "" || clientID == "" || redirectURI == "" {
		c.String(400, "Missing parameters")
		return
	}
	user := s.findUserByEmail(sub)
	if user == nil {
		c.String(400, "Invalid user")
		return
	}
	code, err := newAuthCode()
	if err != nil {
		c.String(500, "Failed to generate authorization code")
		return
	}
	authTime := time.Now().Unix()
	s.authMux.Lock()
	s.authCodes[code] = authCodeData{
		User:                *user,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ExpiresAt:           time.Now().Add(authCodeTTL),
		Nonce:               nonce,
		AuthTime:            authTime,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	}
	s.authMux.Unlock()
	u, err := url.Parse(redirectURI)
	if err != nil {
		c.String(400, "Invalid redirect_uri")
		return
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	c.Redirect(302, u.String())
}

func (s *Server) handleToken(c *gin.Context) {
	code := c.PostForm("code")
	clientID := c.PostForm("client_id")
	redirectURI := c.PostForm("redirect_uri")
	codeVerifier := c.PostForm("code_verifier")
	s.authMux.Lock()
	auth, ok := s.authCodes[code]
	if !ok || auth.ExpiresAt.Before(time.Now()) {
		s.authMux.Unlock()
		c.String(400, "Invalid or expired code")
		return
	}
	if clientID != auth.ClientID {
		s.authMux.Unlock()
		c.String(400, "Invalid client_id for code")
		return
	}
	delete(s.authCodes, code)
	s.authMux.Unlock()
	// Spec-forgiving checks: real OIDC providers reject these; mocc warns and
	// proceeds so existing test harnesses keep working, but the deviation is
	// visible in logs so bugs surface before hitting a hardened provider.
	if redirectURI != "" && redirectURI != auth.RedirectURI {
		log.Printf("[warn] /token redirect_uri %q does not match /authorize %q — a real provider would reject this", redirectURI, auth.RedirectURI)
	} else if redirectURI == "" && auth.RedirectURI != "" {
		log.Printf("[warn] /token missing redirect_uri — a real provider would reject this (expected %q)", auth.RedirectURI)
	}
	if auth.CodeChallenge == "" && codeVerifier != "" {
		log.Printf("[warn] /token received code_verifier but /authorize had no code_challenge — a real provider would reject this")
	}
	if err := verifyPKCE(auth, codeVerifier); err != nil {
		c.String(400, err.Error())
		return
	}
	claims := tokenClaims(auth.User, issuer(c), clientID)
	if auth.Nonce != "" {
		claims["nonce"] = auth.Nonce
	}
	if auth.AuthTime > 0 {
		claims["auth_time"] = auth.AuthTime
	}
	token, err := s.Keys.SignIDToken(claims)
	if err != nil {
		c.String(500, "Failed to sign token")
		return
	}
	resp := map[string]string{"access_token": token, "id_token": token, "token_type": "Bearer", "expires_in": "300"}
	c.JSON(200, resp)
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
	claims := tokenClaims(*selected, issuer(c), "")
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

func (s *Server) handleUserInfo(c *gin.Context) {
	tokenString, err := extractBearerToken(c.Request)
	if err != nil {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+truncateDisplay(err.Error(), 120)+`"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method %s", token.Method.Alg())
		}
		return s.Keys.Public, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	if err != nil || parsedToken == nil || !parsedToken.Valid {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+truncateDisplay(fmt.Sprintf("token validation failed: %v", err), 120)+`"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		c.Header("WWW-Authenticate", `Bearer error="invalid_token", error_description="unsupported claims type"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
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
		c.Header("WWW-Authenticate", `Bearer error="invalid_token", error_description="token missing subject claims"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}

	response := filterUserInfoClaims(claims)
	response["sub"] = sub

	if user := s.findUserBySub(sub); user != nil {
		if user.Email != "" {
			if _, exists := response["email"]; !exists {
				response["email"] = user.Email
			}
		}
		if user.Name != "" {
			if _, exists := response["name"]; !exists {
				response["name"] = user.Name
			}
		}
		for k, v := range user.Claims {
			if _, exists := response[k]; !exists {
				response[k] = v
			}
		}
	}

	c.JSON(http.StatusOK, response)
}

func (s *Server) handleDiscovery(c *gin.Context) {
	issuer := issuer(c)
	config := map[string]interface{}{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/jwks.json",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
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
	reserved := map[string]struct{}{
		"iss": {}, "aud": {}, "iat": {}, "exp": {}, "nbf": {}, "jti": {},
		"azp": {}, "at_hash": {}, "c_hash": {}, "auth_time": {},
	}
	result := make(map[string]interface{})
	for k, v := range claims {
		if _, skip := reserved[k]; skip {
			continue
		}
		if k == "sub" {
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
