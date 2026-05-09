package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"mocc/internal/moccconfig"
)

func newAuthCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func verifyPKCE(auth authCodeData, codeVerifier string) error {
	if auth.CodeChallenge == "" {
		return nil
	}
	if codeVerifier == "" {
		return errors.New("Missing code_verifier for PKCE-protected code")
	}

	switch strings.ToUpper(auth.CodeChallengeMethod) {
	case "S256":
		h := sha256.Sum256([]byte(codeVerifier))
		if base64.RawURLEncoding.EncodeToString(h[:]) != auth.CodeChallenge {
			return errors.New("Invalid code_verifier")
		}
	case "", "PLAIN":
		if codeVerifier != auth.CodeChallenge {
			return errors.New("Invalid code_verifier")
		}
	default:
		return errors.New("Unsupported code_challenge_method")
	}
	return nil
}

func issuer(c *gin.Context) string {
	return fmt.Sprintf("http://%s", c.Request.Host)
}

func tokenClaims(user moccconfig.User, issuer, audience string) jwt.MapClaims {
	claims := jwt.MapClaims{
		"sub":   user.Sub,
		"email": user.Email,
		"iss":   issuer,
	}
	if audience != "" {
		claims["aud"] = audience
	}
	if user.Name != "" {
		claims["name"] = user.Name
	}
	applyExtraClaims(claims, user.Claims)
	return claims
}

func applyExtraClaims(dst jwt.MapClaims, extras map[string]interface{}) {
	if len(extras) == 0 || extras == nil {
		return
	}
	for k, v := range extras {
		dst[k] = v
	}
}
