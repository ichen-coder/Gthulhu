package rest

import (
	"net/http"
)

// TokenResponse represents the response structure for JWT token generation
type TokenResponse struct {
	Token     string `json:"token,omitempty"`
	ExpiredAt int64  `json:"expired_at,omitempty"`
}

// TokenRequest represents the request structure for JWT token generation
type TokenRequest struct {
	ClientID        string `json:"client_id"`            // Client identifier
	ClientAssertion string `json:"client_assertion"`     // JWT signed by the trusted client key
	ExpiredAt       int64  `json:"expired_at,omitempty"` // Deprecated
	PublicKey       string `json:"public_key,omitempty"` // Deprecated
}

// GenTokenHandler handles JWT token generation upon public key verification
func (h Handler) GenTokenHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req TokenRequest
	err := h.JSONBind(r, &req)
	if err != nil {
		h.ErrorResponse(ctx, w, http.StatusBadRequest, "Invalid request payload", err)
		return
	}
	token, expiredAt, err := h.Service.VerifyAndGenerateToken(r.Context(), req.ClientID, req.ClientAssertion)
	if err != nil {
		h.ErrorResponse(ctx, w, http.StatusUnauthorized, "Public key verification failed ", err)
		return
	}

	resp := TokenResponse{
		ExpiredAt: expiredAt,
		Token:     token,
	}
	h.JSONResponse(ctx, w, http.StatusOK, NewSuccessResponse[TokenResponse](&resp))
}
