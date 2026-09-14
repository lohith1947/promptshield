//go:build windows

package proxy

import (
	"syscall"
	"time"
	"unsafe"
)

// WindowsDialog shows a native Yes/No message box and auto-returns "block"
// after Timeout when the user does not answer.
type WindowsDialog struct {
	Timeout time.Duration
}

// Ask returns true when the user chose "Yes" (send it anyway), false when they
// chose "No" or the dialog timed out.
func (d WindowsDialog) Ask(title, message string) (bool, error) {
	const (
		mbYesNo       = 0x00000004
		mbIconWarning = 0x00000030
		mbDefButton2  = 0x00000100
		mbTopmost     = 0x00040000
		idYes         = 6
	)

	textPtr, err := syscall.UTF16PtrFromString(message)
	if err != nil {
		return false, err
	}
	titlePtr, err := syscall.UTF16PtrFromString(title)
	if err != nil {
		return false, err
	}

	// 0 = wait forever; otherwise milliseconds.
	ms := uintptr(0)
	if d.Timeout > 0 {
		ms = uintptr(d.Timeout / time.Millisecond)
	}

	user32 := syscall.NewLazyDLL("user32.dll")
	box := user32.NewProc("MessageBoxTimeoutW")
	ret, _, _ := box.Call(
		0, // hWnd: NULL (no owner)
		uintptr(unsafe.Pointer(textPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		mbYesNo|mbIconWarning|mbDefButton2|mbTopmost,
		0, // wLanguageId: current UI language
		ms,
	)

	return ret == idYes, nil
}