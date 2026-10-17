// SPDX-FileCopyrightText: 2025 Gthulhu Team
//
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// TokenStorage represents the stored token information.
type TokenStorage struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// getTokenFilePath returns the path to the token storage file.
func getTokenFilePath() (string, error) {
	// Use /tmp for temporary token storage (auto-cleared on reboot)
	// Include user ID to avoid conflicts in multi-user systems
	userID := os.Getuid()
	tokenFile := filepath.Join("/tmp", fmt.Sprintf("gthulhu-token-%d.json", userID))

	return tokenFile, nil
}

// SaveToken persists the token to disk.
func SaveToken(token string, expiresAt time.Time) error {
	tokenFile, err := getTokenFilePath()
	if err != nil {
		return err
	}

	storage := TokenStorage{
		Token:     token,
		ExpiresAt: expiresAt,
	}

	data, err := json.MarshalIndent(storage, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal token: %w", err)
	}

	if err := atomicWritePrivateFile(tokenFile, data); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}

	return nil
}

// LoadToken retrieves the token from disk if it exists and is not expired.
func LoadToken() (string, time.Time, error) {
	tokenFile, err := getTokenFilePath()
	if err != nil {
		return "", time.Time{}, err
	}

	if err := ensurePrivateRegularFile(tokenFile); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", time.Time{}, nil
		}
		return "", time.Time{}, fmt.Errorf("validate token file: %w", err)
	}

	data, err := os.ReadFile(tokenFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "", time.Time{}, nil // No token stored yet
		}
		return "", time.Time{}, fmt.Errorf("read token file: %w", err)
	}

	var storage TokenStorage
	if err := json.Unmarshal(data, &storage); err != nil {
		return "", time.Time{}, fmt.Errorf("unmarshal token: %w", err)
	}

	// Check if token is expired
	if time.Now().After(storage.ExpiresAt) {
		return "", time.Time{}, nil // Token expired
	}

	return storage.Token, storage.ExpiresAt, nil
}

// ClearToken removes the stored token.
func ClearToken() error {
	tokenFile, err := getTokenFilePath()
	if err != nil {
		return err
	}

	if err := os.Remove(tokenFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove token file: %w", err)
	}

	return nil
}

func atomicWritePrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		_ = tmpFile.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmpFile.Write(data); err != nil {
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func ensurePrivateRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("token file must not be a symlink")
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("token file must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("token file permissions are too permissive: %o", info.Mode().Perm())
	}
	return nil
}
