package bootstrap

import (
	"debug/pe"
	"encoding/binary"
	"errors"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/version"
)

// Our numeric RCDATA resource is generated from the same VERSION file embedded
// by the agent. Legacy binaries without it have an unknown application version.
func artifactVersion(file *pe.File) string {
	section := file.Section(".rsrc")
	if section == nil || section.Size > 1<<20 {
		return ""
	}
	data, e := section.Data()
	if e != nil {
		return ""
	}
	child := func(offset uint32, id uint32) (uint32, error) {
		if uint64(offset)+16 > uint64(len(data)) {
			return 0, errors.New("resource bounds")
		}
		n := uint32(binary.LittleEndian.Uint16(data[offset+12:])) + uint32(binary.LittleEndian.Uint16(data[offset+14:]))
		if n > 512 || uint64(offset)+16+uint64(n)*8 > uint64(len(data)) {
			return 0, errors.New("resource entries")
		}
		for i := uint32(0); i < n; i++ {
			p := offset + 16 + i*8
			if binary.LittleEndian.Uint32(data[p:]) == id {
				return binary.LittleEndian.Uint32(data[p+4:]), nil
			}
		}
		return 0, errors.New("resource missing")
	}
	offset := uint32(0)
	for _, id := range []uint32{10, 100} {
		v, e := child(offset, id)
		if e != nil || v&0x80000000 == 0 {
			return ""
		}
		offset = v & 0x7fffffff
	}
	entry, e := child(offset, 0)
	if e != nil || entry&0x80000000 != 0 || uint64(entry)+16 > uint64(len(data)) {
		return ""
	}
	rva, size := binary.LittleEndian.Uint32(data[entry:]), binary.LittleEndian.Uint32(data[entry+4:])
	if rva < section.VirtualAddress || size > 128 {
		return ""
	}
	start := rva - section.VirtualAddress
	if uint64(start)+uint64(size) > uint64(len(data)) {
		return ""
	}
	s := string(data[start : start+size])
	s = stringTrim(s)
	if !version.Valid(s) {
		return ""
	}
	return s
}
func stringTrim(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
