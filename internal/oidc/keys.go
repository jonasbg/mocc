package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"log"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type KeySet struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
	KeyID   string
}

func GenerateKeySet() *KeySet {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("RSA key generation failed: %v", err)
	}
	pub := &priv.PublicKey
	hash := sha256.Sum256(pub.N.Bytes())
	kid := base64.URLEncoding.EncodeToString(hash[:])[:8]
	return &KeySet{Private: priv, Public: pub, KeyID: kid}
}

func (ks *KeySet) JWKS() map[string]interface{} {
	n := base64.RawURLEncoding.EncodeToString(ks.Public.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(ks.Public.E)).Bytes())
	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": ks.KeyID,
				"n":   n,
				"e":   e,
			},
		},
	}
}

// SignIDToken signs a jwt with provided claims and returns the compact token string.
func (ks *KeySet) SignIDToken(claims jwt.MapClaims) (string, error) {
	now := time.Now()
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = now.Unix()
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = now.Add(5 * time.Minute).Unix()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = ks.KeyID
	return token.SignedString(ks.Private)
}
