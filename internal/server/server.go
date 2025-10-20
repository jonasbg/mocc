package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v5"

	"mocc/internal/config"
	"mocc/internal/oidc"
	"mocc/internal/templates"
)

type Server struct {
	Engine    *gin.Engine
	Templates map[string]*template.Template
	Users     []config.User
	Keys      *oidc.KeySet
	authCodes map[string]authCodeData
	authMux   sync.Mutex
}

type authCodeData struct {
	User                config.User
	ClientID            string
	ExpiresAt           time.Time
	CodeChallenge       string
	CodeChallengeMethod string
}

func New(users []config.User, keys *oidc.KeySet) *Server {
	// load templates from embedded FS
	t := templates.LoadTemplates()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	s := &Server{Engine: r, Templates: t, Users: users, Keys: keys, authCodes: map[string]authCodeData{}}

	r.Use(gin.Recovery())
	r.Use(requestLogger())
	r.Use(ignoreClientDisconnects())

	// static handler: serve embedded assets first, then try several on-disk locations for dev
	r.GET("/static/*any", func(c *gin.Context) {
		path := c.Param("any")
		if path == "" || path == "/" {
			c.String(404, "")
			return
		}
		clean := strings.TrimPrefix(path, "/")

		// try embedded FS (assets/static/clean) first
		if f, err := templates.TemplatesFS.Open("assets/static/" + clean); err == nil {
			defer f.Close()
			data, _ := io.ReadAll(f)
			// prefer extension-based MIME type (css should be text/css)
			ext := filepath.Ext(clean)
			contentType := ""
			if ext != "" {
				contentType = mime.TypeByExtension(ext)
			}
			if contentType == "" {
				contentType = http.DetectContentType(data)
			}
			c.Data(200, contentType, data)
			return
		}

		// fallback to on-disk locations (dev): check common candidate paths
		candidates := []string{
			"internal/templates/assets/static/" + clean,
		}
		for _, p := range candidates {
			if df, derr := os.Open(p); derr == nil {
				defer df.Close()
				data, _ := io.ReadAll(df)
				ext := filepath.Ext(p)
				contentType := ""
				if ext != "" {
					contentType = mime.TypeByExtension(ext)
				}
				if contentType == "" {
					contentType = http.DetectContentType(data)
				}
				c.Data(200, contentType, data)
				return
			}
		}

		c.Status(404)
	})

	// routes
	r.GET("/", s.handleIndex)
	r.GET("/authorize", s.handleAuthorizeGet)
	r.POST("/authorize", s.handleAuthorizePost)
	r.POST("/token", s.handleToken)
	r.GET("/token/:email", s.handleTokenByEmail)
	r.GET("/login", s.handleLoginRedirect)
	r.GET("/jwks.json", s.handleJWKS)
	r.GET("/userinfo", s.handleUserInfo)
	r.GET("/.well-known/openid-configuration", s.handleDiscovery)

	return s
}

// Handler implementations are intentionally compacted and reference Server state directly.
// The full implementations follow previous behavior and use jwt via Keys.

func (s *Server) handleLoginRedirect(c *gin.Context) {
	u := url.URL{Path: "/authorize", RawQuery: c.Request.URL.RawQuery}
	c.Redirect(302, u.String())
}

func (s *Server) handleIndex(c *gin.Context) {
	t := s.Templates["index.html"]
	if t == nil {
		c.String(500, "template not found")
		return
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(200)
	t.ExecuteTemplate(c.Writer, "layout.html", gin.H{"Users": s.Users})
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
	t := s.Templates["login.html"]
	if t == nil {
		c.String(500, "template not found")
		return
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(200)
	t.ExecuteTemplate(c.Writer, "layout.html", gin.H{
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
	codeChallenge := c.PostForm("code_challenge")
	codeChallengeMethod := c.PostForm("code_challenge_method")
	if sub == "" || clientID == "" || redirectURI == "" {
		c.String(400, "Missing parameters")
		return
	}
	var user *config.User
	for _, u := range s.Users {
		if u.Email == sub {
			user = &u
			break
		}
	}
	if user == nil {
		c.String(400, "Invalid user")
		return
	}
	b := make([]byte, 32)
	rand.Read(b)
	code := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
	s.authMux.Lock()
	s.authCodes[code] = authCodeData{User: *user, ClientID: clientID, ExpiresAt: time.Now().Add(5 * time.Minute), CodeChallenge: codeChallenge, CodeChallengeMethod: codeChallengeMethod}
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
	if auth.CodeChallenge != "" {
		if codeVerifier == "" {
			c.String(400, "Missing code_verifier for PKCE-protected code")
			return
		}
		method := stringsToUpper(auth.CodeChallengeMethod)
		switch method {
		case "S256":
			h := sha256.Sum256([]byte(codeVerifier))
			computed := base64.RawURLEncoding.EncodeToString(h[:])
			if computed != auth.CodeChallenge {
				c.String(400, "Invalid code_verifier")
				return
			}
		case "", "PLAIN":
			if codeVerifier != auth.CodeChallenge {
				c.String(400, "Invalid code_verifier")
				return
			}
		default:
			c.String(400, "Unsupported code_challenge_method")
			return
		}
	}
	issuer := fmt.Sprintf("http://%s", c.Request.Host)
	claims := jwt.MapClaims{"sub": auth.User.Sub, "email": auth.User.Email, "iss": issuer, "aud": clientID}
	if auth.User.Name != "" {
		claims["name"] = auth.User.Name
	}
	applyExtraClaims(claims, auth.User.Claims)
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
	var selected *config.User
	for i := range s.Users {
		if s.Users[i].Email == email {
			selected = &s.Users[i]
			break
		}
	}
	if selected == nil {
		c.String(404, "User not found")
		return
	}
	issuer := fmt.Sprintf("http://%s", c.Request.Host)
	claims := jwt.MapClaims{
		"sub":   selected.Sub,
		"email": selected.Email,
		"iss":   issuer,
	}
	if selected.Name != "" {
		claims["name"] = selected.Name
	}
	applyExtraClaims(claims, selected.Claims)
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
	issuer := fmt.Sprintf("http://%s", c.Request.Host)
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

// helper small wrappers to avoid extra imports in this patch
func stringsToUpper(s string) string { return strings.ToUpper(s) }

func applyExtraClaims(dst jwt.MapClaims, extras map[string]interface{}) {
	if len(extras) == 0 || extras == nil {
		return
	}
	for k, v := range extras {
		dst[k] = v
	}
}

func requestLogger() gin.HandlerFunc {
	interestingKeys := []string{
		"response_type",
		"client_id",
		"redirect_uri",
		"scope",
		"state",
		"nonce",
		"code_challenge",
		"code_challenge_method",
		"grant_type",
		"code",
		"code_verifier",
	}

	return func(c *gin.Context) {
		c.Next()

		method := c.Request.Method
		path := c.Request.URL.Path
		status := c.Writer.Status()

		details := make([]string, 0, len(interestingKeys))
		for _, key := range interestingKeys {
			if val := c.Query(key); val != "" {
				details = append(details, fmt.Sprintf("%s=%s", key, truncateDisplay(val, 60)))
				continue
			}
			if val := c.PostForm(key); val != "" {
				details = append(details, fmt.Sprintf("%s=%s", key, truncateDisplay(val, 60)))
			}
		}

		if loc := c.Writer.Header().Get("Location"); loc != "" {
			details = append(details, fmt.Sprintf("location=%s", truncateDisplay(loc, 80)))
		}

		msg := fmt.Sprintf("%s %s -> %d", method, path, status)
		if len(details) > 0 {
			msg = fmt.Sprintf("%s [%s]", msg, strings.Join(details, " "))
		}

		log.Println(msg)
	}
}

func ignoreClientDisconnects() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if len(c.Errors) == 0 {
			return
		}
		filtered := c.Errors[:0]
		for _, err := range c.Errors {
			if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
				continue
			}
			filtered = append(filtered, err)
		}
		c.Errors = filtered
	}
}

func truncateDisplay(val string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(val)
	if len(runes) <= limit {
		return val
	}
	if limit == 1 {
		return string(runes[0])
	}
	return string(runes[:limit-1]) + "…"
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

func (s *Server) findUserBySub(sub string) *config.User {
	for i := range s.Users {
		if s.Users[i].Sub == sub || s.Users[i].Email == sub {
			return &s.Users[i]
		}
	}
	return nil
}
