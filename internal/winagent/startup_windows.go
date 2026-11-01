package winagent

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/installstate"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const approvalKey = `Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`
const uninstallKey = `Software\Microsoft\Windows\CurrentVersion\Uninstall`

func checkStartupPolicy() error {
	for _, hive := range []registry.Key{registry.LOCAL_MACHINE, registry.CURRENT_USER} {
		key, e := registry.OpenKey(hive, `Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`, registry.QUERY_VALUE)
		if errors.Is(e, registry.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		blocked, _, e := key.GetIntegerValue("DisableCurrentUserRun")
		key.Close()
		if errors.Is(e, registry.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		if blocked != 0 {
			return errors.New("Windows policy prevents this user's sign-in startup")
		}
		return nil
	}
	return nil
}
func addStartup(executable string) (err error) {
	command := windows.EscapeArg(executable) + " run"
	if len(utf16.Encode([]rune(command))) > 260 {
		return errors.New("installation path is too long for Windows sign-in startup")
	}
	if err = checkStartupPolicy(); err != nil {
		return err
	}
	key, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	oldCommand, _, e := key.GetStringValue(serviceName)
	existed := e == nil
	if e != nil && !errors.Is(e, registry.ErrNotExist) {
		return e
	}
	if existed && oldCommand != command {
		return errors.New("another Zireael-RMM installation owns the startup entry; uninstall it first")
	}
	approval, _, err := registry.CreateKey(registry.CURRENT_USER, approvalKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer approval.Close()
	oldApproval, _, e := approval.GetBinaryValue(serviceName)
	approvedExisted := e == nil
	if e != nil && !errors.Is(e, registry.ErrNotExist) {
		return e
	}
	defer func() {
		if err != nil {
			if existed {
				_ = key.SetStringValue(serviceName, oldCommand)
			} else {
				_ = key.DeleteValue(serviceName)
			}
			if approvedExisted {
				_ = approval.SetBinaryValue(serviceName, oldApproval)
			} else {
				_ = approval.DeleteValue(serviceName)
			}
		}
	}()
	if err = key.SetStringValue(serviceName, command); err != nil {
		return err
	}
	enabled := make([]byte, 12)
	enabled[0] = 2
	// Explicit install/repair only. The running agent never reverses a later user choice.
	if err = approval.SetBinaryValue(serviceName, enabled); err != nil {
		return err
	}
	value, _, err := key.GetStringValue(serviceName)
	if err != nil {
		return err
	}
	state, _, err := approval.GetBinaryValue(serviceName)
	if err != nil {
		return err
	}
	if value != command || !installstate.StartupEnabled(state) {
		return errors.New("Windows did not enable Zireael-RMM sign-in startup")
	}
	return nil
}
func removeStartup(executable string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	if err == nil {
		defer key.Close()
		value, _, e := key.GetStringValue(serviceName)
		if e != nil && !errors.Is(e, registry.ErrNotExist) {
			return e
		}
		if e == nil && value != windows.EscapeArg(executable)+" run" {
			return errors.New("another installation owns the startup entry")
		}
		if e == nil {
			if e = key.DeleteValue(serviceName); e != nil {
				return e
			}
		}
	}
	for _, path := range []string{approvalKey, strings.TrimSuffix(approvalKey, `Run`) + `Run32`} {
		k, e := registry.OpenKey(registry.CURRENT_USER, path, registry.SET_VALUE)
		if errors.Is(e, registry.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		e = k.DeleteValue(serviceName)
		k.Close()
		if e != nil && !errors.Is(e, registry.ErrNotExist) {
			return fmt.Errorf("remove startup state: %w", e)
		}
	}
	return nil
}

func checkStartupOwnership(executable string) error {
	key, e := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if errors.Is(e, registry.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	defer key.Close()
	value, _, e := key.GetStringValue(serviceName)
	if errors.Is(e, registry.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if value != windows.EscapeArg(executable)+" run" {
		return errors.New("another user installation owns startup; uninstall it or use the clean replacement command")
	}
	return nil
}

func verifyStartup(executable string) error {
	if e := checkStartupPolicy(); e != nil {
		return e
	}
	key, e := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if e != nil {
		return e
	}
	value, _, e := key.GetStringValue(serviceName)
	key.Close()
	if e != nil {
		return e
	}
	approval, e := registry.OpenKey(registry.CURRENT_USER, approvalKey, registry.QUERY_VALUE)
	if e != nil {
		return e
	}
	state, _, e := approval.GetBinaryValue(serviceName)
	approval.Close()
	if e != nil {
		return e
	}
	if value != windows.EscapeArg(executable)+" run" || !installstate.StartupEnabled(state) {
		return errors.New("Windows sign-in startup is not enabled")
	}
	return nil
}
