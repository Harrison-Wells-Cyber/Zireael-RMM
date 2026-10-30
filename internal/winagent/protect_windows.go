package winagent

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func security(machine bool) (*windows.SecurityAttributes, error) {
	sddl := "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	if windows.GetCurrentProcessToken().IsElevated() {
		sddl = "O:BAG:BA" + sddl
	}
	if !machine {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return nil, err
		}
		access := "FA"
		// An elevated installer must not launch code that its filtered user token
		// can replace. Normal sign-in still needs read/execute access to the files.
		if windows.GetCurrentProcessToken().IsElevated() {
			access = "FRFX"
		}
		sddl += "(A;OICI;" + access + ";;;" + user.User.Sid.String() + ")"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

// Reject junctions/reparse points before installing privileged executable content.
func noReparse(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		p, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return err
		}
		attrs, err := windows.GetFileAttributes(p)
		if err != nil {
			return err
		}
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("installation paths through junctions or symlinks are unsupported")
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

func createDirectory(path string, machine bool) error {
	if err := noReparse(filepath.Dir(path)); err != nil {
		return err
	}
	attributes, err := security(machine)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// CreateDirectory is exclusive: never repurpose a pre-existing directory.
	return windows.CreateDirectory(p, attributes)
}

func protect(data []byte, machine bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty configuration")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	flags := uint32(windows.CRYPTPROTECT_UI_FORBIDDEN)
	if machine {
		flags |= windows.CRYPTPROTECT_LOCAL_MACHINE
	}
	if err := windows.CryptProtectData(&in, nil, nil, 0, nil, flags, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func unprotect(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data) > 128<<10 {
		return nil, errors.New("invalid protected configuration size")
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
