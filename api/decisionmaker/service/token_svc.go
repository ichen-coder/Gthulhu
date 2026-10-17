package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Gthulhu/api/pkg/logger"
	"github.com/Gthulhu/api/pkg/util"
	"github.com/golang-jwt/jwt/v5"
)

const (
	DMClientAssertionAudience = "gthulhu-decision-maker-token"
	DMAccessTokenAudience     = "gthulhu-decision-maker-api"
	DMAccessTokenIssuer       = "decision-maker-service"
	DMAccessTokenType         = "dm_access"
	DMClientAssertionType     = "dm_client_assertion"
)

// VerifyAndGenerateToken verifies the provided public key and generates a JWT token if valid
func (svc *Service) VerifyAndGenerateToken(ctx context.Context, clientID string, clientAssertion string) (string, int64, error) {
	err := svc.VerifyClientAssertion(clientID, clientAssertion)
	if err != nil {
		return "", 0, fmt.Errorf("client assertion verification failed: %v", err)
	}
	token, claims, err := svc.generateJWT(ctx, clientID)
	if err != nil {
		return "", 0, fmt.Errorf("JWT generation failed: %v", err)
	}
	return token, claims.ExpiresAt.Unix(), nil
}

// VerifyClientAssertion verifies a signed client assertion from the trusted manager key.
func (svc *Service) VerifyClientAssertion(clientID string, clientAssertion string) error {
	if strings.TrimSpace(clientID) == "" {
		return fmt.Errorf("client ID is required")
	}
	if strings.TrimSpace(clientAssertion) == "" {
		return fmt.Errorf("client assertion is required")
	}
	if expected := strings.TrimSpace(svc.tokenConfig.ExpectedClientID); expected != "" && clientID != expected {
		return fmt.Errorf("unauthorized client ID")
	}

	rsaPublicKey, err := util.PEMToRSAPublicKey(svc.tokenConfig.TrustedClientPublicKey.Value())
	if err != nil {
		return fmt.Errorf("failed to parse trusted client public key: %v", err)
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(clientAssertion, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaPublicKey, nil
	})
	if err != nil {
		return err
	}
	if !token.Valid {
		return fmt.Errorf("invalid client assertion")
	}
	if claims.TokenType != DMClientAssertionType {
		return fmt.Errorf("invalid client assertion type")
	}
	if claims.ClientID != clientID || claims.Subject != clientID || claims.Issuer != clientID {
		return fmt.Errorf("client assertion subject mismatch")
	}
	if !hasAudience(claims.Audience, DMClientAssertionAudience) {
		return fmt.Errorf("invalid client assertion audience")
	}
	return nil
}

// generateJWT generates a JWT token for authenticated client
func (svc *Service) generateJWT(ctx context.Context, clientID string) (string, Claims, error) {
	expireHr := svc.tokenConfig.TokenDurationHr
	if expireHr <= 0 {
		logger.Logger(ctx).Warn().Msgf("invalid token duration hr %d, defaulting to 24 hours", expireHr)
		expireHr = 24 // default to 24 hours
	}

	claims := Claims{
		ClientID:  clientID,
		TokenType: DMAccessTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(expireHr) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    DMAccessTokenIssuer,
			Subject:   clientID,
			Audience:  jwt.ClaimStrings{DMAccessTokenAudience},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenStr, err := token.SignedString(svc.jwtPrivateKey)
	if err != nil {
		return "", Claims{}, fmt.Errorf("failed to sign JWT token: %v", err)
	}
	return tokenStr, claims, nil
}

// Claims represents JWT token claims
type Claims struct {
	ClientID  string `json:"client_id"`
	TokenType string `json:"token_type,omitempty"`
	jwt.RegisteredClaims
}

func hasAudience(audiences []string, expected string) bool {
	for _, audience := range audiences {
		if audience == expected {
			return true
		}
	}
	return false
}
