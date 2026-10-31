package desktop

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"image"
	"runtime"
	"sort"
	"sync"
	"time"
	"unsafe"
)

var user32 = windows.NewLazySystemDLL("user32.dll")
var gdi32 = windows.NewLazySystemDLL("gdi32.dll")
var enumMonitors = user32.NewProc("EnumDisplayMonitors")
var monitorInfo = user32.NewProc("GetMonitorInfoW")
var getDC = user32.NewProc("GetDC")
var releaseDC = user32.NewProc("ReleaseDC")
var createDC = gdi32.NewProc("CreateCompatibleDC")
var createDIB = gdi32.NewProc("CreateDIBSection")
var selectObject = gdi32.NewProc("SelectObject")
var deleteObject = gdi32.NewProc("DeleteObject")
var deleteDC = gdi32.NewProc("DeleteDC")
var bitBlt = gdi32.NewProc("BitBlt")
var gdiFlush = gdi32.NewProc("GdiFlush")
var getCursor = user32.NewProc("GetCursorInfo")
var getIcon = user32.NewProc("GetIconInfo")
var drawIcon = user32.NewProc("DrawIconEx")
var openInput = user32.NewProc("OpenInputDesktop")
var closeDesktop = user32.NewProc("CloseDesktop")
var objectInfo = user32.NewProc("GetUserObjectInformationW")
var getThreadDesktop = user32.NewProc("GetThreadDesktop")
var setThreadDesktop = user32.NewProc("SetThreadDesktop")
var metrics = user32.NewProc("GetSystemMetrics")

type rect struct{ L, T, R, B int32 }
type monInfo struct {
	Size          uint32
	Monitor, Work rect
	Flags         uint32
	Device        [32]uint16
}
type bitmapInfo struct {
	Size                   uint32
	Width, Height          int32
	Planes, BitCount       uint16
	Compression, SizeImage uint32
	XPels, YPels           int32
	Used, Important        uint32
}
type cursorInfo struct {
	Size, Flags uint32
	Cursor      uintptr
	X, Y        int32
}
type iconInfo struct {
	Icon        int32
	X, Y        uint32
	Mask, Color uintptr
}
type windowsBackend struct {
	inputMu                  sync.Mutex
	screen, dc, bitmap, old  uintptr
	pixels                   unsafe.Pointer
	size                     image.Point
	rgba                     *image.RGBA
	keys                     map[string]bool
	buttons                  map[int]bool
	dx                       *duplication
	dxMonitor                uint32
	dxFailed                 bool
	dxRetry                  time.Time
	lastCapture              time.Time
	desktop, originalDesktop uintptr
	interrupted              bool
	releasePending           bool // Protected by inputMu, like keys and buttons.
}

func NewWindowsBackend() Backend {
	return &windowsBackend{keys: map[string]bool{}, buttons: map[int]bool{}}
}
func PrepareThread() {
	runtime.LockOSThread()
	user32.NewProc("SetThreadDpiAwarenessContext").Call(^uintptr(3))
}
func (b *windowsBackend) Elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }
func (b *windowsBackend) Monitors() ([]Monitor, error) {
	var result []Monitor

	ok, _, e := enumMonitors.Call(0, 0, monitorCallback, uintptr(unsafe.Pointer(&result)))
	if ok == 0 {
		return nil, e
	}
	if len(result) > 16 {
		return nil, errors.New("too many displays")
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Label < result[j].Label })
	for i := range result {
		result[i].ID = uint32(i + 1)
	}
	return result, nil
}
func (b *windowsBackend) prepareDesktop() error {
	if e := b.attachDesktop(); e != nil {
		b.interrupted = true
		b.resetDX()
		b.closeSurface()
		b.lastCapture = time.Time{}
		return e
	}
	if b.interrupted {
		// Retry releases that Windows rejected while the secure desktop was up.
		b.Release()
		b.interrupted = false
		b.dxFailed = false
	}
	return nil
}
func (b *windowsBackend) attachDesktop() error {
	// READOBJECTS | CREATEWINDOW | WRITEOBJECTS. Only bind to Default, even
	// when this worker's token could open the secure desktop.
	h, _, e := openInput.Call(0, 0, 0x83)
	if h == 0 {
		return &CaptureError{"session_locked", e}
	}
	keep := false
	defer func() {
		if !keep {
			closeDesktop.Call(h)
		}
	}()
	var name [256]uint16
	var n uint32
	ok, _, e := objectInfo.Call(h, 2, uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Sizeof(name)), uintptr(unsafe.Pointer(&n)))
	if ok == 0 || windows.UTF16ToString(name[:]) != "Default" {
		return &CaptureError{"desktop_unavailable", e}
	}
	current, _, e := getThreadDesktop.Call(uintptr(windows.GetCurrentThreadId()))
	if current == 0 {
		return &CaptureError{"desktop_unavailable", e}
	}
	var receivesInput int32
	ok, _, _ = objectInfo.Call(current, 6, uintptr(unsafe.Pointer(&receivesInput)), unsafe.Sizeof(receivesInput), uintptr(unsafe.Pointer(&n)))
	if current != 0 && ok != 0 && receivesInput != 0 {
		return nil
	}
	// Drop thread-bound graphics resources before rebinding after a switch.
	b.resetDX()
	b.closeSurface()
	b.lastCapture = time.Time{}
	ok, _, e = setThreadDesktop.Call(h)
	if ok == 0 {
		return &CaptureError{"desktop_unavailable", e}
	}
	if b.originalDesktop == 0 {
		b.originalDesktop = current // Borrowed handle; never close it.
	}
	if b.desktop != 0 {
		closeDesktop.Call(b.desktop)
	}
	b.desktop = h
	b.dxFailed = false
	keep = true
	return nil
}
func (b *windowsBackend) surface(m Monitor) error {
	if b.dc != 0 && b.size.X == int(m.Width) && b.size.Y == int(m.Height) {
		return nil
	}
	b.closeSurface()
	b.screen, _, _ = getDC.Call(0)
	if b.screen == 0 {
		return errors.New("GetDC failed")
	}
	b.dc, _, _ = createDC.Call(b.screen)
	if b.dc == 0 {
		b.closeSurface()
		return errors.New("CreateCompatibleDC failed")
	}
	info := bitmapInfo{Size: 40, Width: int32(m.Width), Height: -int32(m.Height), Planes: 1, BitCount: 32}
	b.bitmap, _, _ = createDIB.Call(b.screen, uintptr(unsafe.Pointer(&info)), 0, uintptr(unsafe.Pointer(&b.pixels)), 0, 0)
	if b.bitmap == 0 {
		b.closeSurface()
		return errors.New("CreateDIBSection failed")
	}
	b.old, _, _ = selectObject.Call(b.dc, b.bitmap)
	if b.old == 0 || b.old == ^uintptr(0) {
		b.closeSurface()
		return errors.New("SelectObject failed")
	}
	b.size = image.Pt(int(m.Width), int(m.Height))
	b.rgba = image.NewRGBA(image.Rect(0, 0, b.size.X, b.size.Y))
	return nil
}
func (b *windowsBackend) Capture(m Monitor, backend string) (image.Image, string, error) {
	if e := b.prepareDesktop(); e != nil {
		return nil, "", e
	}
	if !m.Valid() {
		return nil, "", &CaptureError{"unsupported_geometry", nil}
	}
	if e := b.surface(m); e != nil {
		return nil, "gdi", e
	}
	name := "gdi"
	cursor := true
	if backend != "gdi" {
		if b.dxMonitor != m.ID {
			b.resetDX()
			b.dxFailed = false
			b.dxMonitor = m.ID
		}
		if b.dxFailed && time.Now().After(b.dxRetry) {
			b.dxFailed = false
		}
		if b.dx == nil && !b.dxFailed {
			d, e := newDuplication(m)
			if e == nil {
				b.dx = d
			} else {
				if deniedDX(e) {
					return nil, "dxgi", &CaptureError{"access_denied", e}
				}
				b.dxFailed = true
				b.dxRetry = time.Now().Add(10 * time.Second)
			}
		}
		if b.dx != nil {
			data, draw, e := b.dx.capture(m)
			if e == nil && data == nil {
				// An idle output may time out even before its first DXGI frame.
				// Seed/reseed the viewer with GDI, then refresh idle displays at
				// least once a second (also covers a new protocol generation).
				if time.Since(b.lastCapture) < time.Second {
					return nil, "dxgi", nil
				}
			}
			if e == nil && data != nil {
				copy(unsafe.Slice((*byte)(b.pixels), int(m.Width*m.Height*4)), data)
				name = "dxgi"
				cursor = draw
			} else if e != nil {
				b.resetDX()
				var code dxError
				if deniedDX(e) || errors.As(e, &code) && (uint32(code) == 0x887a0026 || uint32(code) == 0x887a0005) {
					b.closeSurface()
					b.lastCapture = time.Time{}
					b.interrupted = true
					return nil, "dxgi", &CaptureError{"desktop_unavailable", e}
				}
				b.dxFailed = true
				b.dxRetry = time.Now().Add(10 * time.Second)
			}
		}
	}
	if name == "gdi" {
		ok, _, e := bitBlt.Call(b.dc, 0, 0, uintptr(m.Width), uintptr(m.Height), b.screen, uintptr(m.X), uintptr(m.Y), 0x40cc0020)
		if ok == 0 {
			b.closeSurface()
			b.lastCapture = time.Time{}
			return nil, name, fmt.Errorf("BitBlt: %w", e)
		}
	}
	if cursor {
		b.cursor(m)
	}
	gdiFlush.Call()
	src := unsafe.Slice((*byte)(b.pixels), int(m.Width*m.Height*4))
	dst := b.rgba.Pix
	for i := 0; i < len(src); i += 4 {
		dst[i], dst[i+1], dst[i+2], dst[i+3] = src[i+2], src[i+1], src[i], 255
	}
	b.lastCapture = time.Now()
	return b.rgba, name, nil
}
func (b *windowsBackend) cursor(m Monitor) {
	var c cursorInfo
	c.Size = uint32(unsafe.Sizeof(c))
	ok, _, _ := getCursor.Call(uintptr(unsafe.Pointer(&c)))
	if ok == 0 || c.Flags&1 == 0 {
		return
	}
	var i iconInfo
	ok, _, _ = getIcon.Call(c.Cursor, uintptr(unsafe.Pointer(&i)))
	if ok == 0 {
		return
	}
	if i.Mask != 0 {
		defer deleteObject.Call(i.Mask)
	}
	if i.Color != 0 {
		defer deleteObject.Call(i.Color)
	}
	drawIcon.Call(b.dc, uintptr(c.X-m.X-int32(i.X)), uintptr(c.Y-m.Y-int32(i.Y)), c.Cursor, 0, 0, 0, 0, 3)
}
func (b *windowsBackend) closeSurface() {
	if b.dc != 0 && b.old != 0 && b.old != ^uintptr(0) {
		selectObject.Call(b.dc, b.old)
	}
	if b.bitmap != 0 {
		deleteObject.Call(b.bitmap)
	}
	if b.dc != 0 {
		deleteDC.Call(b.dc)
	}
	if b.screen != 0 {
		releaseDC.Call(0, b.screen)
	}
	b.screen, b.dc, b.bitmap, b.old = 0, 0, 0, 0
	b.pixels = nil
	b.rgba = nil
}
func (b *windowsBackend) resetDX() {
	if b.dx != nil {
		b.dx.close()
		b.dx = nil
	}
}
func (b *windowsBackend) Close() {
	b.resetDX()
	b.closeSurface()
	if b.desktop != 0 {
		if ok, _, _ := setThreadDesktop.Call(b.originalDesktop); ok != 0 {
			closeDesktop.Call(b.desktop)
			b.desktop = 0
		}
	}
}

var monitorCallback = windows.NewCallback(func(handle, dc, r uintptr, result *[]Monitor) uintptr {
	var info monInfo
	info.Size = uint32(unsafe.Sizeof(info))
	ok, _, _ := monitorInfo.Call(handle, uintptr(unsafe.Pointer(&info)))
	if ok != 0 {
		m := Monitor{Label: windows.UTF16ToString(info.Device[:]), X: info.Monitor.L, Y: info.Monitor.T, Width: uint32(info.Monitor.R - info.Monitor.L), Height: uint32(info.Monitor.B - info.Monitor.T)}
		if Dimensions(m.Width, m.Height, 16384) {
			*result = append(*result, m)
		}
	}
	return 1
})

func deniedDX(err error) bool {
	var code dxError
	return errors.As(err, &code) && (uint32(code) == 0x80070005 || uint32(code) == 0x887a0028)
}
