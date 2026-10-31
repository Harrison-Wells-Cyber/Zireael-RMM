package desktop

import (
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

// The COM ABI and method indices follow the Windows SDK interfaces. References
// and pinned revisions are listed in REMOTE_DESKTOP_ARCHITECTURE.md.
type comObject struct{ table *[64]uintptr }

func call(o *comObject, index int, args ...uintptr) uintptr {
	a := append([]uintptr{uintptr(unsafe.Pointer(o))}, args...)
	r, _, _ := syscall.SyscallN(o.table[index], a...)
	return r
}
func release(o *comObject) {
	if o != nil {
		call(o, 2)
	}
}

type dxError uint32

func (e dxError) Error() string { return fmt.Sprintf("DXGI HRESULT 0x%08x", uint32(e)) }
func hr(r uintptr) error {
	if int32(r) < 0 {
		return dxError(uint32(r))
	}
	return nil
}
func guid(s string) *windows.GUID { v, _ := windows.GUIDFromString(s); return &v }

var iidFactory = guid("{770aae78-f26f-4dba-a829-253c83d1b387}")
var iidOutput = guid("{00cddea8-939b-4b83-a340-a685226666cc}")
var iidTexture = guid("{6f15aaf2-d208-4e89-9ab4-489535d34f9c}")

type outputDesc struct {
	Name               [32]uint16
	Bounds             rect
	Attached, Rotation uint32
	Monitor            uintptr
}
type textureDesc struct{ Width, Height, Mips, ArraySize, Format, SampleCount, SampleQuality, Usage, Bind, CPU, Misc uint32 }
type frameInfo struct {
	Present, Mouse               int64
	Frames, Coalesced, Protected uint32
	X, Y                         int32
	Visible, Metadata, Shape     uint32
}
type mappedTexture struct {
	Data                 unsafe.Pointer
	RowPitch, DepthPitch uint32
}
type duplication struct {
	device, context, dup, staging *comObject
	desc                          textureDesc
	rotation                      uint32
	pixels                        []byte
}

func newDuplication(m Monitor) (*duplication, error) {
	var factory *comObject
	r, _, _ := windows.NewLazySystemDLL("dxgi.dll").NewProc("CreateDXGIFactory1").Call(uintptr(unsafe.Pointer(iidFactory)), uintptr(unsafe.Pointer(&factory)))
	if e := hr(r); e != nil {
		return nil, e
	}
	defer release(factory)
	for a := 0; a < 16; a++ {
		var adapter *comObject
		if hr(call(factory, 12, uintptr(a), uintptr(unsafe.Pointer(&adapter)))) != nil {
			break
		}
		for n := 0; n < 16; n++ {
			var output *comObject
			if hr(call(adapter, 7, uintptr(n), uintptr(unsafe.Pointer(&output)))) != nil {
				break
			}
			var desc outputDesc
			e := hr(call(output, 7, uintptr(unsafe.Pointer(&desc))))
			if e != nil || desc.Attached == 0 || desc.Bounds.L != m.X || desc.Bounds.T != m.Y || desc.Bounds.R-desc.Bounds.L != int32(m.Width) || desc.Bounds.B-desc.Bounds.T != int32(m.Height) {
				release(output)
				continue
			}
			d, e := createDuplication(adapter, output, desc.Rotation)
			release(output)
			release(adapter)
			return d, e
		}
		release(adapter)
	}
	return nil, fmt.Errorf("DXGI output not found")
}
func createDuplication(adapter, output *comObject, rotation uint32) (d *duplication, err error) {
	d = &duplication{rotation: rotation}
	allocated := d
	defer func() {
		if err != nil {
			allocated.close()
		}
	}()
	create := windows.NewLazySystemDLL("d3d11.dll").NewProc("D3D11CreateDevice")
	r, _, _ := create.Call(uintptr(unsafe.Pointer(adapter)), 0, 0, 0x20, 0, 0, 7, uintptr(unsafe.Pointer(&d.device)), 0, uintptr(unsafe.Pointer(&d.context)))
	if err = hr(r); err != nil {
		return nil, err
	}
	var out1 *comObject
	err = hr(call(output, 0, uintptr(unsafe.Pointer(iidOutput)), uintptr(unsafe.Pointer(&out1))))
	if err != nil {
		return nil, err
	}
	defer release(out1)
	err = hr(call(out1, 22, uintptr(unsafe.Pointer(d.device)), uintptr(unsafe.Pointer(&d.dup))))
	if err != nil {
		return nil, err
	}
	return d, nil
}
func (d *duplication) capture(m Monitor) ([]byte, bool, error) {
	var info frameInfo
	var resource *comObject
	r := call(d.dup, 8, 50, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&resource)))
	if uint32(r) == 0x887a0027 {
		return nil, false, nil
	}
	if e := hr(r); e != nil {
		return nil, false, e
	}
	defer call(d.dup, 14)
	defer release(resource)
	var texture *comObject
	if e := hr(call(resource, 0, uintptr(unsafe.Pointer(iidTexture)), uintptr(unsafe.Pointer(&texture)))); e != nil {
		return nil, false, e
	}
	defer release(texture)
	var desc textureDesc
	call(texture, 10, uintptr(unsafe.Pointer(&desc)))
	if desc.Format != 87 || !Dimensions(desc.Width, desc.Height, 16384) {
		return nil, false, fmt.Errorf("unsupported DXGI format or dimensions")
	}
	if d.rotation <= 1 && (desc.Width != m.Width || desc.Height != m.Height) {
		return nil, false, ErrProtocol
	}
	if d.rotation == 2 || d.rotation == 4 {
		if desc.Width != m.Height || desc.Height != m.Width {
			return nil, false, ErrProtocol
		}
	}
	if d.staging == nil || d.desc.Width != desc.Width || d.desc.Height != desc.Height {
		release(d.staging)
		d.staging = nil
		desc.Mips = 1
		desc.ArraySize = 1
		desc.SampleCount = 1
		desc.SampleQuality = 0
		desc.Usage = 3
		desc.Bind = 0
		desc.CPU = 0x20000
		desc.Misc = 0
		if e := hr(call(d.device, 5, uintptr(unsafe.Pointer(&desc)), 0, uintptr(unsafe.Pointer(&d.staging)))); e != nil {
			return nil, false, e
		}
		d.desc = desc
		d.pixels = make([]byte, int(m.Width*m.Height*4))
	}
	call(d.context, 47, uintptr(unsafe.Pointer(d.staging)), uintptr(unsafe.Pointer(texture)))
	var mapped mappedTexture
	if e := hr(call(d.context, 14, uintptr(unsafe.Pointer(d.staging)), 0, 1, 0, uintptr(unsafe.Pointer(&mapped)))); e != nil {
		return nil, false, e
	}
	defer call(d.context, 15, uintptr(unsafe.Pointer(d.staging)), 0)
	if mapped.Data == nil || mapped.RowPitch < desc.Width*4 || mapped.RowPitch > 1<<20 {
		return nil, false, ErrProtocol
	}
	src := unsafe.Slice((*byte)(mapped.Data), int(mapped.RowPitch)*int(desc.Height))
	w, h := int(m.Width), int(m.Height)
	sw, sh := int(desc.Width), int(desc.Height)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			sx, sy := x, y
			switch d.rotation {
			case 2:
				sx, sy = y, sh-1-x
			case 3:
				sx, sy = sw-1-x, sh-1-y
			case 4:
				sx, sy = sw-1-y, x
			}
			if sx < 0 || sy < 0 || sx >= sw || sy >= sh {
				return nil, false, ErrProtocol
			}
			copy(d.pixels[(y*w+x)*4:][:4], src[sy*int(mapped.RowPitch)+sx*4:][:4])
		}
	}
	return d.pixels, info.Visible != 0, nil
}
func (d *duplication) close() {
	release(d.staging)
	release(d.dup)
	release(d.context)
	release(d.device)
	d.staging, d.dup, d.context, d.device = nil, nil, nil, nil
	d.pixels = nil
}
