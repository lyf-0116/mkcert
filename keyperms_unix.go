//go:build !windows

package main

import (
	"fmt"
	"os"
	"strings"
)

func checkPrivateKeyFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return privateKeyPermissionError(path, fmt.Sprintf("it is not a regular file (mode %s)", info.Mode()))
	}

	perm := info.Mode().Perm()
	if perm&0077 != 0 {
		return privateKeyPermissionError(path, fmt.Sprintf(
			"its permissions are %04o; group and other users must have no access", perm))
	}
	if perm&0400 == 0 {
		return privateKeyPermissionError(path, fmt.Sprintf(
			"its permissions are %04o; the owner must have read access", perm))
	}
	return nil
}

func privateKeyRepairCommand(path string) string {
	return "chmod 600 " + shellSingleQuote(path)
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
