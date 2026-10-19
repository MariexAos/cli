// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

//go:build darwin || linux

package auth

import "github.com/larksuite/cli/internal/keychain"

// tokenStorageRootDir returns the directory holding the encrypted user tokens,
// including its LARKSUITE_CLI_DATA_DIR override where the platform honors it.
func tokenStorageRootDir() (string, error) {
	return keychain.StorageDir(keychain.LarkCliService), nil
}
