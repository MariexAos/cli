// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package auth

import (
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/larksuite/cli/internal/keychain"
)

// tokenStorageRootDir returns a per-user directory for token storage locks.
// Windows stores user tokens in HKCU, which one OS user shares regardless of
// LARKSUITE_CLI_DATA_DIR or process environment, so the lock uses the user's
// Local AppData known folder rather than the overridable %LocalAppData%.
func tokenStorageRootDir() (string, error) {
	directory, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", err
	}
	return filepath.Join(directory, keychain.LarkCliService), nil
}
