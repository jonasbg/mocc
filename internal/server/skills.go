package server

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func (s *Server) baseURL(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	host := c.Request.Host
	if fwdHost := c.GetHeader("X-Forwarded-Host"); fwdHost != "" {
		if i := strings.IndexByte(fwdHost, ','); i >= 0 {
			fwdHost = fwdHost[:i]
		}
		host = strings.TrimSpace(fwdHost)
	}
	return scheme + "://" + host
}

func (s *Server) handleSkillMd(c *gin.Context) {
	exampleEmail := "alice.admin@test.local"
	if len(s.Users) > 0 {
		exampleEmail = s.Users[0].Email
	}
	data := map[string]interface{}{
		"BaseURL":      s.baseURL(c),
		"Users":        s.Users,
		"ExampleEmail": exampleEmail,
	}
	c.Header("Content-Type", "text/markdown; charset=utf-8")
	c.Status(http.StatusOK)
	if err := s.SkillTemplate.Execute(c.Writer, data); err != nil {
		log.Printf("skill template execute: %v", err)
	}
}

func (s *Server) handleSkillsIndex(c *gin.Context) {
	base := s.baseURL(c)
	c.JSON(http.StatusOK, gin.H{
		"version": "1",
		"skills": []gin.H{
			{
				"name":        "mocc-auth",
				"description": "Authenticate against this mocc mock OIDC provider. Mint test tokens, run the authorization code flow, and pick a test user.",
				"type":        "skill-md",
				"url":         base + skillMDPath,
			},
		},
	})
}

func (s *Server) handleSkillRedirect(c *gin.Context) {
	c.Redirect(http.StatusFound, skillMDPath)
}
