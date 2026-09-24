package rest

import (
	"net/http"
	"strings"
	"testing"
)

func TestJSONBindRejectsTrailingJSON(t *testing.T) {
	h := &Handler{}
	var dst struct {
		Name string `json:"name"`
	}
	req, err := http.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"ok"}{"name":"bad"}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if err := h.JSONBind(req, &dst); err == nil {
		t.Fatal("expected trailing JSON to be rejected")
	}
}
