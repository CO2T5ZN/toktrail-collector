//go:build windows

package scheduler

import (
	"errors"
	"fmt"
	"syscall"
)

// windowsPrincipalUserID resolves the account identity written into the
// Windows task principal's UserId element: the SID of the user who owns
// the current process token (advapi32 OpenProcessToken / GetTokenInformation
// / ConvertSidToStringSid through the standard library). This is the same
// identity schtasks registers the task under when no /RU override is
// passed. It never consults USERNAME/USERDOMAIN or any other environment
// variable, so the value cannot be forged through the environment, and the
// Task Scheduler accepts SID strings in UserId (task XML exported by
// schtasks itself carries SIDs there).
//
// It is a variable so tests can inject a deterministic identity when
// simulating the Windows renderer; the Windows integration test exercises
// the real resolution.
var windowsPrincipalUserID = func() (string, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return "", fmt.Errorf("open current process token: %w", err)
	}
	defer token.Close()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read current process token user: %w", err)
	}
	sid, err := tokenUser.User.Sid.String()
	if err != nil {
		return "", fmt.Errorf("render current user SID: %w", err)
	}
	if sid == "" {
		return "", errors.New("current process token user SID is empty")
	}
	return sid, nil
}
