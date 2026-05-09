package server

import (
	"errors"
	"fmt"
	"strings"
	"syscall"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

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

func agentDiscoveryLinks() gin.HandlerFunc {
	entries := []struct{ href, rel string }{
		{skillIndexPath, "agent-skills"},
	}
	parts := make([]string, 0, len(entries))
	for _, e := range entries {
		parts = append(parts, fmt.Sprintf(`<%s>; rel=%q`, e.href, e.rel))
	}
	header := strings.Join(parts, ", ")
	return func(c *gin.Context) {
		c.Writer.Header().Add("Link", header)
		c.Next()
	}
}

func CORS(origins []string) gin.HandlerFunc {
	corsConfig := cors.DefaultConfig()
	if len(origins) == 0 {
		origins = []string{"*"}
	}
	corsConfig.AllowOrigins = origins
	corsConfig.AddAllowHeaders("authorization")
	return cors.New(corsConfig)
}
