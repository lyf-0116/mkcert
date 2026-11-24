package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

// checkPrivateKeyPermissions verifies that a private key file is protected by
// the platform's file permission or access-control model.
func checkPrivateKeyPermissions(path string) error {
	return checkPrivateKeyFilePermissions(path)
}

func privateKeyPermissionError(path, problem string) error {
	return fmt.Errorf("insecure permissions on private key %q: %s\n\nRefusing to use it until it is restricted. Fix it with:\n\n    %s",
		path, problem, privateKeyRepairCommand(path))
}

// writePrivateKeyFile writes private key material and verifies that the
// resulting file is only accessible to trusted principals. An existing file
// is checked before it is truncated so an over-broad key is not replaced
// before the operator has a chance to remediate it.
func writePrivateKeyFile(path string, data []byte, perm os.FileMode) error {
	if pathExists(path) {
		if err := checkPrivateKeyPermissions(path); err != nil {
			return err
		}
	}
	if err := ioutil.WriteFile(path, data, perm); err != nil {
		return err
	}
	return checkPrivateKeyPermissions(path)
}

// readPrivateKeyFile checks permissions immediately before reading a private
// key. Callers must use this instead of reading the path directly so that
// existing deployments with loose permissions are detected on every use.
func readPrivateKeyFile(path string) ([]byte, error) {
	if err := checkPrivateKeyPermissions(path); err != nil {
		return nil, err
	}
	return ioutil.ReadFile(path)
}
