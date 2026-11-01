package winagent

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/agent"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/installstate"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func startInstalled(dir, mode string) error {
	executable := filepath.Join(dir, installedExecutableName)
	if mode == "service" {
		return startExistingService(executable)
	}
	return launchUserAgent(dir)
}
func repairInstallation(dir string, invite agent.Invite) error {
	config, _, e := loadFrom(dir)
	if e != nil {
		return fmt.Errorf("old installation cannot be read; use the clean replacement option or uninstall first: %w", e)
	}
	if !installstate.Matching(config, invite) {
		return errors.New("existing installation belongs to a different server or mode; uninstall it or use explicit replacement")
	}
	if e = config.Validate(); e != nil {
		return fmt.Errorf("old identity cannot be reused; use clean replacement: %w", e)
	}
	restoreRegistration, e := snapshotRegistration(dir, config.Mode)
	if e != nil {
		return e
	}
	root, e := openInstallation(dir)
	if e != nil {
		return e
	}
	defer root.Close()
	current, e := os.Executable()
	if e != nil {
		return e
	}
	if samePath(current, filepath.Join(dir, installedExecutableName)) {
		return errors.New("run repair from the deployment command, outside the installed directory")
	}
	data, e := os.ReadFile(current)
	if e != nil {
		return e
	}
	stop := func() error { return stopInstallation(dir, config.Mode) }
	activate := func() error {
		if e := registerUninstaller(dir, config.Mode); e != nil {
			return e
		}
		if config.Mode == "user" {
			if e := addStartup(filepath.Join(dir, installedExecutableName)); e != nil {
				return e
			}
		}
		if e := startInstalled(dir, config.Mode); e != nil {
			return e
		}
		if config.Mode == "user" {
			return verifyStartup(filepath.Join(dir, installedExecutableName))
		}
		return nil
	}
	restore := func() error {
		if e := restoreRegistration(); e != nil {
			return e
		}
		return startInstalled(dir, config.Mode)
	}
	if e = installstate.Upgrade(root, data, stop, activate, restore); e != nil {
		return e
	}
	for _, name := range []string{"desktop-engine.exe", "desktop.js", "DESKTOP-NOTICES.txt"} {
		if e = root.Remove(name); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	fmt.Println("Zireael-RMM updated. Existing device identity and approval were preserved.")
	return nil
}

func startExistingService(executable string) error {
	manager, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer manager.Disconnect()
	service, e := manager.OpenService(serviceName)
	if e != nil {
		return e
	}
	defer service.Close()
	config, e := service.Config()
	if e != nil {
		return e
	}
	if config.BinaryPathName != windows.EscapeArg(executable)+" service" {
		return errors.New("another installation owns the Windows service")
	}
	if config.StartType != mgr.StartAutomatic {
		config.StartType = mgr.StartAutomatic
		config.DelayedAutoStart = true
		if e = service.UpdateConfig(config); e != nil {
			return e
		}
	}
	if e = service.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second}, {Type: mgr.ServiceRestart, Delay: time.Minute}}, 86400); e != nil {
		return e
	}
	if e = service.Start(); e != nil {
		return e
	}
	return waitServiceRunning(service)
}

func launchUserAgent(dir string) error {
	config, _, e := loadFrom(dir)
	if e != nil {
		return e
	}
	executable := filepath.Join(dir, installedExecutableName)
	child := exec.Command(executable, "run")
	child.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	if e = child.Start(); e != nil {
		return e
	}
	defer child.Process.Release()
	handle, e := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(child.Process.Pid))
	if e != nil {
		child.Process.Kill()
		return e
	}
	defer windows.CloseHandle(handle)
	name, e := eventName(config.DeviceID)
	if e != nil {
		child.Process.Kill()
		return e
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		state, e := windows.WaitForSingleObject(handle, 0)
		if e != nil {
			return e
		}
		if state == windows.WAIT_OBJECT_0 {
			return errors.New("agent exited during startup")
		}
		event, err := windows.OpenEvent(windows.SYNCHRONIZE, false, name)
		if err == nil {
			windows.CloseHandle(event)
			return nil
		}
		if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			windows.TerminateProcess(handle, 1)
			return err
		}
		if time.Now().After(deadline) {
			windows.TerminateProcess(handle, 1)
			return errors.New("agent did not finish local initialization")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func waitServiceRunning(service *mgr.Service) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		status, e := service.Query()
		if e != nil {
			return e
		}
		if status.State == svc.Running {
			return nil
		}
		if status.State == svc.Stopped {
			return errors.New("Windows service stopped during initialization")
		}
		if time.Now().After(deadline) {
			return errors.New("Windows service did not finish initialization")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
