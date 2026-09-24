package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/Gthulhu/api/config"
	"github.com/Gthulhu/api/pkg/util"
	"github.com/golang-jwt/jwt/v5"
)

func TestVerifyAndGenerateTokenRequiresSignedAssertion(t *testing.T) {
	managerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(manager): %v", err)
	}
	dmKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey(dm): %v", err)
	}
	managerPubPEM, err := util.RSAPublicKeyToPEM(&managerKey.PublicKey)
	if err != nil {
		t.Fatalf("RSAPublicKeyToPEM: %v", err)
	}

	svc := &Service{
		jwtPrivateKey: dmKey,
		tokenConfig: config.TokenConfig{
			TrustedClientPublicKey: config.SecretValue(managerPubPEM),
			ExpectedClientID:       "manager-client",
			TokenDurationHr:        1,
		},
	}

	assertion := signAssertion(t, managerKey, "manager-client")
	token, _, err := svc.VerifyAndGenerateToken(context.Background(), "manager-client", assertion)
	if err != nil {
		t.Fatalf("VerifyAndGenerateToken(valid): %v", err)
	}
	if token == "" {
		t.Fatal("expected signed access token")
	}

	if _, _, err := svc.VerifyAndGenerateToken(context.Background(), "manager-client", "not-a-jwt"); err == nil {
		t.Fatal("expected invalid assertion to be rejected")
	}
}

func signAssertion(t *testing.T, key *rsa.PrivateKey, clientID string) string {
	t.Helper()
	now := time.Now()
	claims := jwt.MapClaims{
		"client_id":  clientID,
		"token_type": DMClientAssertionType,
		"iss":        clientID,
		"sub":        clientID,
		"aud":        []string{DMClientAssertionAudience},
		"iat":        now.Unix(),
		"nbf":        now.Unix(),
		"exp":        now.Add(time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return tokenString
}
