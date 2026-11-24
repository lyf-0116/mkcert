//go:build windows

package main

import (
	"errors"
	"fmt"
	"os/user"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func checkPrivateKeyFilePermissions(path string) error {
	securityInfo := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, securityInfo)
	if err != nil {
		return fmt.Errorf("failed to inspect Windows security descriptor: %w", err)
	}

	trustedSIDs := map[string]struct{}{
		"S-1-5-18":     {}, // NT AUTHORITY\SYSTEM
		"S-1-5-32-544": {}, // BUILTIN\Administrators
	}
	if currentUser, err := user.Current(); err == nil && currentUser.Uid != "" {
		if currentSID, err := windows.StringToSid(currentUser.Uid); err == nil {
			trustedSIDs[currentSID.String()] = struct{}{}
		}
	}

	if owner, _, err := sd.Owner(); err == nil && owner != nil {
		ownerSID := owner.String()
		if isBroadWindowsSID(ownerSID) {
			return privateKeyPermissionError(path, fmt.Sprintf("the owner %s is a broad security principal", ownerSID))
		}
		if ownerSID != "" {
			trustedSIDs[ownerSID] = struct{}{}
		}
	}

	dacl, _, err := sd.DACL()
	if err != nil && !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return fmt.Errorf("failed to inspect Windows DACL: %w", err)
	}
	if dacl == nil {
		// A present but NULL DACL grants access to everyone. An empty,
		// non-nil ACL with zero ACEs instead denies all access.
		return privateKeyPermissionError(path, "the DACL is NULL, which allows every principal access")
	}

	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("failed to inspect Windows DACL entry %d: %w", i, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}

		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		sidString := sid.String()
		if _, trusted := trustedSIDs[sidString]; trusted {
			continue
		}
		if windowsACEAllowsRead(ace.Mask) {
			return privateKeyPermissionError(path, fmt.Sprintf(
				"Windows ACL grants read access to untrusted principal SID %s", sidString))
		}
	}

	return nil
}

func windowsACEAllowsRead(mask windows.ACCESS_MASK) bool {
	readBits := windows.FILE_READ_DATA | windows.GENERIC_READ | windows.GENERIC_ALL
	return uint32(mask)&uint32(readBits) != 0
}

func isBroadWindowsSID(sid string) bool {
	switch sid {
	case "S-1-1-0", // Everyone
		"S-1-5-2",      // Network
		"S-1-5-4",      // Interactive
		"S-1-5-7",      // Anonymous logon
		"S-1-5-11",     // Authenticated Users
		"S-1-5-32-545", // BUILTIN\Users
		"S-1-5-32-546": // BUILTIN\Guests
		return true
	}
	return strings.HasPrefix(sid, "S-1-15-2-") // AppContainer and application package SIDs
}

func privateKeyRepairCommand(path string) string {
	principal := `%USERDOMAIN%\%USERNAME%`
	if currentUser, err := user.Current(); err == nil && currentUser.Username != "" {
		principal = currentUser.Username
	}
	quotedPath := windowsQuote(path)
	quotedGrant := windowsQuote(principal + ":R")
	return "icacls " + quotedPath + " /reset\n" +
		"    icacls " + quotedPath + " /inheritance:r /grant:r " + quotedGrant
}

func windowsQuote(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}
