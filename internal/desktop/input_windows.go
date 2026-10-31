package desktop

import (
	"errors"
	"unicode/utf16"
	"unsafe"
)

var sendInput = user32.NewProc("SendInput")

// Both supported architectures use an 8-byte-aligned union and 40-byte INPUT.
type winInput struct {
	Kind uint32
	Pad  uint32
	Data [32]byte
}
type mouseInput struct {
	X, Y              int32
	Data, Flags, Time uint32
	Extra             uintptr
}
type keyInput struct {
	VK, Scan    uint16
	Flags, Time uint32
	Extra       uintptr
}

func inject(i *winInput) error {
	n, _, _ := sendInput.Call(1, uintptr(unsafe.Pointer(i)), unsafe.Sizeof(*i))
	if n != 1 {
		return errors.New("SendInput did not insert event")
	}
	return nil
}
func sendKey(code uint16, down, unicode bool) error {
	i := winInput{Kind: 1}
	k := (*keyInput)(unsafe.Pointer(&i.Data[0]))
	k.Scan = code & 255
	k.Flags = 8
	if unicode {
		k.Scan = code
		k.Flags = 4
	} else if code&0x100 != 0 {
		k.Flags |= 1
	}
	if !down {
		k.Flags |= 2
	}
	return inject(&i)
}
func (b *windowsBackend) Input(c Control, m Monitor, w, h uint32) error {
	b.inputMu.Lock()
	defer b.inputMu.Unlock()
	if e := ordinaryDesktop(); e != nil {
		return e
	}
	switch c.Type {
	case "key":
		held := b.keys[c.Code]
		if c.Down && held && !c.Repeat {
			return nil
		}
		if !c.Down && !held {
			return nil
		}
		if e := sendKey(ScanCodes[c.Code], c.Down, false); e != nil {
			return e
		}
		if c.Down {
			b.keys[c.Code] = true
		} else {
			delete(b.keys, c.Code)
		}
	case "text":
		for _, ch := range utf16.Encode([]rune(c.Text)) {
			if e := sendKey(ch, true, true); e != nil {
				return e
			}
			if e := sendKey(ch, false, true); e != nil {
				return e
			}
		}
	case "pointer":
		get := func(n uintptr) int32 { v, _, _ := metrics.Call(n); return int32(v) }
		x, y, ok := MapPoint(c.X, c.Y, w, h, m, get(76), get(77), uint32(get(78)), uint32(get(79)))
		if !ok {
			return ErrProtocol
		}
		i := winInput{}
		p := (*mouseInput)(unsafe.Pointer(&i.Data[0]))
		p.X, p.Y = x, y
		p.Flags = 0xc001
		switch c.Action {
		case "down", "up":
			if (c.Action == "down") == b.buttons[c.Button] {
				return nil
			}
			flags, data, ok := mouseButtonFlags(c.Button, c.Action == "down")
			if !ok {
				return ErrProtocol
			}
			p.Flags |= flags
			p.Data = data
		case "wheel":
			p.Flags |= 0x800
			p.Data = uint32(c.Delta)
		}
		if e := inject(&i); e != nil {
			return e
		}
		if c.Action == "down" {
			b.buttons[c.Button] = true
		}
		if c.Action == "up" {
			delete(b.buttons, c.Button)
		}
	}
	return nil
}
func (b *windowsBackend) Release() {
	b.inputMu.Lock()
	defer b.inputMu.Unlock()
	for code := range b.keys {
		_ = sendKey(ScanCodes[code], false, false)
		delete(b.keys, code)
	}
	for button := range b.buttons {
		i := winInput{}
		p := (*mouseInput)(unsafe.Pointer(&i.Data[0]))
		p.Flags, p.Data, _ = mouseButtonFlags(button, false)
		_ = inject(&i)
		delete(b.buttons, button)
	}
}
