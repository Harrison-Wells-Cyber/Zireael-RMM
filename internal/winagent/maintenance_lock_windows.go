package winagent

import (
	"errors"
	"golang.org/x/sys/windows"
	"runtime"
)

func maintenanceLock() (func(), error) {
	runtime.LockOSThread()
	var handles []windows.Handle
	release := func() {
		for i := len(handles) - 1; i >= 0; i-- {
			windows.ReleaseMutex(handles[i])
			windows.CloseHandle(handles[i])
		}
		runtime.UnlockOSThread()
	}
	user, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		release()
		return nil, e
	}
	names := []string{`Global\ZireaelRMM-Maintenance-` + user.User.Sid.String()}
	if windows.GetCurrentProcessToken().IsElevated() {
		names = append(names, `Global\ZireaelRMM-Maintenance-Machine`)
	}
	for _, name := range names {
		machine := name == `Global\ZireaelRMM-Maintenance-Machine`
		attributes, e := security(machine)
		if e != nil {
			release()
			return nil, e
		}
		text, e := windows.UTF16PtrFromString(name)
		if e != nil {
			release()
			return nil, e
		}
		h, e := windows.CreateMutex(attributes, false, text)
		if e != nil && !errors.Is(e, windows.ERROR_ALREADY_EXISTS) {
			if h != 0 {
				windows.CloseHandle(h)
			}
			release()
			return nil, e
		}
		state, e := windows.WaitForSingleObject(h, 0)
		if e != nil || state != windows.WAIT_OBJECT_0 && state != windows.WAIT_ABANDONED {
			windows.CloseHandle(h)
			release()
			return nil, errors.New("another Zireael-RMM install or uninstall is running")
		}
		handles = append(handles, h)
	}
	return release, nil
}
