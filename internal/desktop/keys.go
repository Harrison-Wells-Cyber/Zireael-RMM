package desktop

// Windows set-1 scan codes. Values with bit 8 set carry the extended-key flag.
var ScanCodes = map[string]uint16{
	"Escape": 1, "Digit1": 2, "Digit2": 3, "Digit3": 4, "Digit4": 5, "Digit5": 6, "Digit6": 7, "Digit7": 8, "Digit8": 9, "Digit9": 10, "Digit0": 11, "Minus": 12, "Equal": 13, "Backspace": 14, "Tab": 15,
	"KeyQ": 16, "KeyW": 17, "KeyE": 18, "KeyR": 19, "KeyT": 20, "KeyY": 21, "KeyU": 22, "KeyI": 23, "KeyO": 24, "KeyP": 25, "BracketLeft": 26, "BracketRight": 27, "Enter": 28, "ControlLeft": 29,
	"KeyA": 30, "KeyS": 31, "KeyD": 32, "KeyF": 33, "KeyG": 34, "KeyH": 35, "KeyJ": 36, "KeyK": 37, "KeyL": 38, "Semicolon": 39, "Quote": 40, "Backquote": 41, "ShiftLeft": 42, "Backslash": 43,
	"KeyZ": 44, "KeyX": 45, "KeyC": 46, "KeyV": 47, "KeyB": 48, "KeyN": 49, "KeyM": 50, "Comma": 51, "Period": 52, "Slash": 53, "ShiftRight": 54, "NumpadMultiply": 55, "AltLeft": 56, "Space": 57, "CapsLock": 58,
	"F1": 59, "F2": 60, "F3": 61, "F4": 62, "F5": 63, "F6": 64, "F7": 65, "F8": 66, "F9": 67, "F10": 68, "NumLock": 69, "ScrollLock": 70, "Numpad7": 71, "Numpad8": 72, "Numpad9": 73, "NumpadSubtract": 74, "Numpad4": 75, "Numpad5": 76, "Numpad6": 77, "NumpadAdd": 78, "Numpad1": 79, "Numpad2": 80, "Numpad3": 81, "Numpad0": 82, "NumpadDecimal": 83, "IntlBackslash": 86, "F11": 87, "F12": 88,
	"NumpadEnter": 0x11c, "ControlRight": 0x11d, "NumpadDivide": 0x135, "PrintScreen": 0x137, "AltRight": 0x138, "Home": 0x147, "ArrowUp": 0x148, "PageUp": 0x149, "ArrowLeft": 0x14b, "ArrowRight": 0x14d, "End": 0x14f, "ArrowDown": 0x150, "PageDown": 0x151, "Insert": 0x152, "Delete": 0x153, "MetaLeft": 0x15b, "MetaRight": 0x15c, "ContextMenu": 0x15d,
}

func SupportedKey(code string) bool { _, ok := ScanCodes[code]; return ok }

// MapPoint maps raster coordinates to the inclusive Windows virtual desktop range.
func MapPoint(x, y int32, w, h uint32, m Monitor, left, top int32, vw, vh uint32) (int32, int32, bool) {
	if w == 0 || h == 0 || vw < 2 || vh < 2 || x < 0 || y < 0 || uint32(x) >= w || uint32(y) >= h {
		return 0, 0, false
	}
	px := int64(m.X)
	py := int64(m.Y)
	if w > 1 {
		px += int64(x) * int64(m.Width-1) / int64(w-1)
	}
	if h > 1 {
		py += int64(y) * int64(m.Height-1) / int64(h-1)
	}
	norm := func(v int64, origin int32, extent uint32) int32 {
		n := (v - int64(origin)) * 65535 / int64(extent-1)
		if n < 0 {
			n = 0
		}
		if n > 65535 {
			n = 65535
		}
		return int32(n)
	}
	return norm(px, left, vw), norm(py, top, vh), true
}
