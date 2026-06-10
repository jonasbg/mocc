package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log"
	"strings"

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
			return errors.New("invalid code_verifier")
		}
	case "", "PLAIN":
		log.Printf("[warn] PKCE code_challenge_method %q in use — prefer S256; 'plain' is for testing only", auth.CodeChallengeMethod)
		if codeVerifier != auth.CodeChallenge {
			return errors.New("invalid code_verifier")
		}
	default:
		return errors.New("unsupported code_challenge_method")
	}
	return nil
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
	for k, v := range extras {
		dst[k] = v
	}
}
