package desktop

import (
	"errors"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var kernel32 = windows.NewLazySystemDLL("kernel32.dll")
var openClipboard = user32.NewProc("OpenClipboard")
var closeClipboard = user32.NewProc("CloseClipboard")
var getClipboardData = user32.NewProc("GetClipboardData")
var setClipboardData = user32.NewProc("SetClipboardData")
var emptyClipboard = user32.NewProc("EmptyClipboard")
var availableClipboard = user32.NewProc("IsClipboardFormatAvailable")
var globalAlloc = kernel32.NewProc("GlobalAlloc")
var globalLock = kernel32.NewProc("GlobalLock")
var globalUnlock = kernel32.NewProc("GlobalUnlock")
var globalSize = kernel32.NewProc("GlobalSize")
var globalFree = kernel32.NewProc("GlobalFree")
var moveClipboardMemory = kernel32.NewProc("RtlMoveMemory")

func acquireClipboard(owner uintptr) error {
	for i := 0; i < 5; i++ {
		if ok, _, _ := openClipboard.Call(owner); ok != 0 {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("clipboard is busy")
}
func (b *windowsBackend) ReadClipboard() (string, error) {
	if e := b.prepareDesktop(); e != nil {
		return "", e
	}
	return readClipboardText()
}
func (b *windowsBackend) WriteClipboard(text string) error {
	if e := b.prepareDesktop(); e != nil {
		return e
	}
	return writeClipboardText(text)
}
func readClipboardText() (string, error) {
	if e := acquireClipboard(0); e != nil {
		return "", e
	}
	defer closeClipboard.Call()
	if present, _, _ := availableClipboard.Call(13); present == 0 {
		return "", nil
	}
	handle, _, e := getClipboardData.Call(13)
	if handle == 0 {
		return "", e
	}
	size, _, _ := globalSize.Call(handle)
	if size < 2 || size%2 != 0 {
		return "", errors.New("invalid clipboard Unicode allocation")
	}
	ptr, _, e := globalLock.Call(handle)
	if ptr == 0 {
		return "", e
	}
	defer globalUnlock.Call(handle)
	units := make([]uint16, int(min(size/2, MaxClipboard+1)))
	moveClipboardMemory.Call(uintptr(unsafe.Pointer(&units[0])), ptr, uintptr(len(units)*2))
	for i, v := range units {
		if v == 0 {
			return string(utf16.Decode(units[:i])), nil
		}
	}
	return "", ErrClipboardTooLarge
}
func writeClipboardText(text string) error {
	if len(text) > MaxClipboard || strings.ContainsRune(text, 0) {
		return ErrProtocol
	}
	// A short-lived message-only window provides the clipboard owner required by
	// EmptyClipboard/SetClipboardData. No window is shown on the user's desktop.
	class, _ := windows.UTF16PtrFromString("STATIC")
	owner, _, e := user32.NewProc("CreateWindowExW").Call(0, uintptr(unsafe.Pointer(class)), 0, 0, 0, 0, 0, 0, ^uintptr(2), 0, 0, 0)
	if owner == 0 {
		return e
	}
	defer user32.NewProc("DestroyWindow").Call(owner)
	if e = acquireClipboard(owner); e != nil {
		return e
	}
	defer closeClipboard.Call()
	units := append(utf16.Encode([]rune(text)), 0)
	handle, _, e := globalAlloc.Call(2, uintptr(len(units)*2))
	if handle == 0 {
		return e
	}
	transferred := false
	defer func() {
		if !transferred {
			globalFree.Call(handle)
		}
	}()
	ptr, _, e := globalLock.Call(handle)
	if ptr == 0 {
		return e
	}
	moveClipboardMemory.Call(ptr, uintptr(unsafe.Pointer(&units[0])), uintptr(len(units)*2))
	globalUnlock.Call(handle)
	if ok, _, e := emptyClipboard.Call(); ok == 0 {
		return e
	}
	if result, _, e := setClipboardData.Call(13, handle); result == 0 {
		return e
	}
	transferred = true
	return nil
}
