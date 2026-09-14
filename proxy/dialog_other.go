//go:build !windows

package proxy

import (
	"errors"
	"time"
)

// WindowsDialog is a no-op on non-Windows platforms. Ask always reports an
// error so callers fail closed (block) instead of hanging on a UI that does
// not exist.
type WindowsDialog struct {
	Timeout time.Duration
}

func (d WindowsDialog) Ask(title, message string) (bool, error) {
	return false, errors.New("interactive confirmation requires Windows")
}