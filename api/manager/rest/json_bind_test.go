package rest

import (
	"net/http"
	"strings"
	"testing"
)

func TestJSONBindRejectsUnknownFields(t *testing.T) {
	h := &Handler{}
	var dst struct {
		Name string `json:"name"`
	}
	req, err := http.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"ok","extra":true}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := h.JSONBind(req, &dst); err == nil {
		t.Fatal("expected unknown field to be rejected")
	}
}
