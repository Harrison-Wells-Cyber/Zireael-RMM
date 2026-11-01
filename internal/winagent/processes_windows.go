package winagent

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func ownedProcesses(dir string) ([]windows.Handle, error) {
	snapshot, e := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if e != nil {
		return nil, e
	}
	defer windows.CloseHandle(snapshot)
	var result []windows.Handle
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for e = windows.Process32First(snapshot, &entry); e == nil; e = windows.Process32Next(snapshot, &entry) {
		if entry.ProcessID == windows.GetCurrentProcessId() {
			continue
		}
		// Most processes cannot possibly be ours; avoid requesting handles to them.
		name := windows.UTF16ToString(entry.ExeFile[:])
		if !samePath(name, installedExecutableName) && !samePath(name, "desktop-engine.exe") && !samePath(name, installedExecutableName+".previous") {
			continue
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, entry.ProcessID)
		if err != nil {
			continue
		}
		var path [32768]uint16
		n := uint32(len(path))
		err = windows.QueryFullProcessImageName(h, 0, &path[0], &n)
		if err == nil && (samePath(windows.UTF16ToString(path[:n]), filepath.Join(dir, installedExecutableName)) || samePath(windows.UTF16ToString(path[:n]), filepath.Join(dir, "desktop-engine.exe")) || samePath(windows.UTF16ToString(path[:n]), filepath.Join(dir, installedExecutableName+".previous"))) {
			result = append(result, h)
		} else {
			windows.CloseHandle(h)
		}
	}
	if e != nil && !errors.Is(e, windows.ERROR_NO_MORE_FILES) {
		for _, h := range result {
			windows.CloseHandle(h)
		}
		return nil, e
	}
	return result, nil
}
func stopOwnedProcesses(dir string) error {
	handles, e := ownedProcesses(dir)
	if e != nil {
		return e
	}
	defer func() {
		for _, h := range handles {
			windows.CloseHandle(h)
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for _, h := range handles {
		remaining := time.Until(deadline)
		if remaining < 0 {
			remaining = 0
		}
		result, e := windows.WaitForSingleObject(h, uint32(remaining.Milliseconds()))
		if e != nil {
			return e
		}
		if result == uint32(windows.WAIT_TIMEOUT) {
			if e = windows.TerminateProcess(h, 0); e != nil {
				return fmt.Errorf("stop old agent: %w", e)
			}
			result, e = windows.WaitForSingleObject(h, 10000)
			if e != nil || result != windows.WAIT_OBJECT_0 {
				return errors.New("old agent process did not stop")
			}
		}
	}
	return nil
}
