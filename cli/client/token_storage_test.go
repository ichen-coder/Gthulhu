package client

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveTokenWritesPrivateFile(t *testing.T) {
	tokenFile, err := getTokenFilePath()
	if err != nil {
		t.Fatalf("getTokenFilePath: %v", err)
	}
	_ = os.Remove(tokenFile)
	t.Cleanup(func() { _ = os.Remove(tokenFile) })

	if err := SaveToken("secret-token", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	info, err := os.Stat(tokenFile)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("permissions=%o, want 600", got)
	}
}

func TestLoadTokenRejectsSymlink(t *testing.T) {
	tokenFile, err := getTokenFilePath()
	if err != nil {
		t.Fatalf("getTokenFilePath: %v", err)
	}
	target := filepath.Join(t.TempDir(), "token.json")
	if err := os.WriteFile(target, []byte(`{"token":"x","expires_at":"2999-01-01T00:00:00Z"}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_ = os.Remove(tokenFile)
	if err := os.Symlink(target, tokenFile); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(tokenFile) })

	if _, _, err := LoadToken(); err == nil {
		t.Fatal("expected LoadToken to reject symlink")
	}
}

func TestAtomicWritePrivateFileCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "token.json")
	if err := atomicWritePrivateFile(path, []byte("token")); err != nil {
		t.Fatalf("atomicWritePrivateFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("permissions=%o, want 600", got)
	}
}
