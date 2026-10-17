package rest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/Gthulhu/api/config"
	"github.com/Gthulhu/api/decisionmaker/service"
	"github.com/golang-jwt/jwt/v5"
)

func TestValidateJWTRejectsWrongTokenType(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tokenConfig := config.TokenConfig{
		RsaPrivateKeyPem: config.SecretValue(encodePrivateKeyPEM(privateKey)),
		ExpectedClientID: "manager-client",
		TokenDurationHr:  1,
	}

	tokenString := signDMToken(t, privateKey, "manager-client", "access", time.Now().Add(time.Minute))
	if _, err := validateJWT(privateKey, tokenConfig, tokenString); err == nil {
		t.Fatal("expected invalid token type to be rejected")
	}
}

func TestValidateJWTAcceptsDecisionMakerToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tokenConfig := config.TokenConfig{
		RsaPrivateKeyPem: config.SecretValue(encodePrivateKeyPEM(privateKey)),
		ExpectedClientID: "manager-client",
		TokenDurationHr:  1,
	}

	tokenString := signDMToken(t, privateKey, "manager-client", service.DMAccessTokenType, time.Now().Add(time.Minute))
	claims, err := validateJWT(privateKey, tokenConfig, tokenString)
	if err != nil {
		t.Fatalf("validateJWT: %v", err)
	}
	if claims.ClientID != "manager-client" {
		t.Fatalf("clientID=%q, want manager-client", claims.ClientID)
	}
}

func signDMToken(t *testing.T, key *rsa.PrivateKey, clientID, tokenType string, expiry time.Time) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, Claims{
		ClientID:  clientID,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    service.DMAccessTokenIssuer,
			Subject:   clientID,
			Audience:  jwt.ClaimStrings{service.DMAccessTokenAudience},
			ExpiresAt: jwt.NewNumericDate(expiry),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	})
	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return tokenString
}

func encodePrivateKeyPEM(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}
