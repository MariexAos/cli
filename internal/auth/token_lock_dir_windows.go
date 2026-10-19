// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package auth

import (
	"os"
	"path/filepath"

	"github.com/larksuite/cli/internal/keychain"
)

// tokenStorageRootDir returns a per-user directory for token storage locks.
// Windows stores user tokens in HKCU, which one OS user shares regardless of
// LARKSUITE_CLI_DATA_DIR, so the lock follows the user cache directory.
func tokenStorageRootDir() (string, error) {
	directory, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, keychain.LarkCliService), nil
}
