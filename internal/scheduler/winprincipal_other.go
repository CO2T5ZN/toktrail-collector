//go:build !windows

package scheduler

import "errors"

// windowsPrincipalUserID cannot resolve a Windows account identity on a
// non-Windows host. Production never renders the windows platform here
// (production passes runtime.GOOS), so failing closed is the correct
// behavior: a Windows task definition is only ever rendered on this
// machine by tests, which stub this variable with a deterministic
// identity.
var windowsPrincipalUserID = func() (string, error) {
	return "", errors.New("current windows account identity is only available on windows")
}
