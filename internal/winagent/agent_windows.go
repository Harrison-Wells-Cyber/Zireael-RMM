// Package winagent implements explicit Windows installation and process lifecycle.
package winagent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/agent"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/identity"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/state"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/wire"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "ZireaelRMM"
const installedExecutableName = "ZireaelRMM.exe"
const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const configName = "identity.dpapi"

func Run(args []string) error {
	command := "run"
	if len(args) > 0 {
		command, args = args[0], args[1:]
	}
	switch command {
	case "install":
		return install(args)
	case "run":
		// Reattach output to the agent's own visible console after a child launch.
		if output, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
			os.Stdout, os.Stderr = output, output
		}
		if len(args) != 0 {
			return errors.New("run accepts no arguments")
		}
		config, _, err := load()
		if err != nil {
			return err
		}
		if config.Mode == "service" {
			return errors.New("service agents must be started through Windows Service Control Manager")
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		return runUser(ctx, config)
	case "service":
		isService, err := svc.IsWindowsService()
		if err != nil {
			return err
		}
		if !isService {
			return errors.New("service entry point requires Service Control Manager")
		}
		return svc.Run(serviceName, &serviceHandler{})
	case "uninstall":
		return uninstall()
	default:
		return errors.New("usage: agent [run | install --mode user|service|temporary | uninstall]")
	}
}

func install(args []string) error {
	f := flag.NewFlagSet("install", flag.ContinueOnError)
	mode := f.String("mode", "user", "user (default), service, or temporary")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || !state.ValidMode(*mode) {
		return errors.New("invalid installation mode")
	}
	machine := *mode == "service"
	if machine && !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("service installation requires an already elevated PowerShell; no elevation was requested")
	}
	encoded, err := io.ReadAll(io.LimitReader(os.Stdin, 32<<10+1))
	if err != nil {
		return err
	}
	if len(encoded) > 32<<10 {
		return errors.New("enrollment configuration too large")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return errors.New("expected console-generated enrollment configuration on stdin")
	}
	var invite agent.Invite
	if json.Unmarshal(raw, &invite) != nil || invite.Mode != *mode || !agent.ValidServer(invite.Server) {
		return errors.New("invalid enrollment configuration or mode mismatch")
	}
	folder := windows.FOLDERID_LocalAppData
	if windows.GetCurrentProcessToken().IsElevated() {
		folder = windows.FOLDERID_ProgramFiles
	}
	base, err := windows.KnownFolderPath(folder, 0)
	if err != nil {
		return err
	}
	name := "ZireaelRMM"
	if *mode == "user" && windows.GetCurrentProcessToken().IsElevated() {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return err
		}
		name += "-User-" + user.User.Sid.String()
	}
	if *mode == "temporary" {
		random := make([]byte, 8)
		_, _ = rand.Read(random)
		name += "-Temporary-" + hex.EncodeToString(random)
	}
	dir := filepath.Join(base, name)
	if err = createDirectory(dir, machine); err != nil {
		return fmt.Errorf("create private installation directory (uninstall an existing installation first): %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(filepath.Join(dir, configName))
			_ = os.Remove(filepath.Join(dir, installedExecutableName))
			for _, name := range []string{"desktop-engine.exe", "desktop.js", "DESKTOP-NOTICES.txt"} {
				_ = os.Remove(filepath.Join(dir, name))
			}
			_ = os.Remove(dir)
		}
	}()
	current, err := os.Executable()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(current)
	if err != nil {
		return err
	}
	executable := filepath.Join(dir, installedExecutableName)
	if err = writeNew(executable, data); err != nil {
		return err
	}
	if err = installDesktop(dir); err != nil {
		return err
	}
	key, csr, err := identity.NewDeviceKey()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var config agent.Config
	for attempt := 0; attempt < 3; attempt++ {
		config, err = agent.Enroll(ctx, invite, key, csr, nil)
		if err == nil || ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("device enrollment failed: %w", err)
	}
	raw, err = json.Marshal(config)
	if err != nil {
		return err
	}
	protected, err := protect(raw, machine)
	if err != nil {
		return err
	}
	if err = writeNew(filepath.Join(dir, configName), protected); err != nil {
		return err
	}
	if machine {
		if err = installService(executable); err != nil {
			return err
		}
	} else {
		if *mode == "user" {
			if err = addStartup(executable); err != nil {
				return err
			}
		}
		child := exec.Command(executable, "run")
		// A visible console provides local status and an ordinary close control.
		child.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE}
		if err = child.Start(); err != nil {
			if *mode == "user" {
				_ = removeStartup(executable)
			}
			return err
		}
		_ = child.Process.Release()
	}
	committed = true
	fmt.Printf("Zireael-RMM installed (%s): %s\n", *mode, executable)
	if config.PendingCode != "" {
		fmt.Printf("Approval needed. Tell your helper this pairing code: %s\n", config.PendingCode)
	}
	if *mode == "temporary" {
		fmt.Println("No startup entry was created. This process stops when support disconnects. Run the installed EXE again for a new session.")
	}
	return nil
}

func addStartup(executable string) error {
	command := windows.EscapeArg(executable) + " run"
	if len([]rune(command)) > 260 {
		return errors.New("installation path is too long for Windows sign-in startup")
	}
	key, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if _, _, err = key.GetStringValue(serviceName); err == nil {
		return errors.New("a Zireael-RMM startup entry already exists")
	} else if !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return key.SetStringValue(serviceName, command)
}

func removeStartup(executable string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer key.Close()
	value, _, err := key.GetStringValue(serviceName)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if value != windows.EscapeArg(executable)+" run" {
		return errors.New("startup entry points to another installation; it was not changed")
	}
	return key.DeleteValue(serviceName)
}

func installService(executable string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.CreateService(serviceName, executable, mgr.Config{StartType: mgr.StartAutomatic, DisplayName: "Zireael-RMM support agent", Description: "Authorized family remote support", ServiceStartName: "LocalSystem", DelayedAutoStart: true}, "service")
	if err != nil {
		return err
	}
	defer service.Close()
	if err = service.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second}, {Type: mgr.ServiceRestart, Delay: time.Minute}}, 86400); err != nil {
		_ = service.Delete()
		return err
	}
	if err = service.Start(); err != nil {
		_ = service.Delete()
		return err
	}
	return nil
}

func load() (agent.Config, string, error) {
	var config agent.Config
	executable, err := os.Executable()
	if err != nil {
		return config, "", err
	}
	dir := filepath.Dir(executable)
	if err = noReparse(dir); err != nil {
		return config, dir, err
	}
	f, err := os.Open(filepath.Join(dir, configName))
	if err != nil {
		return config, dir, fmt.Errorf("no installed identity; use the console-generated installation command: %w", err)
	}
	defer f.Close()
	protected, err := io.ReadAll(io.LimitReader(f, 128<<10+1))
	if err != nil {
		return config, dir, err
	}
	raw, err := unprotect(protected)
	if err != nil {
		return config, dir, err
	}
	if err = json.Unmarshal(raw, &config); err != nil {
		return config, dir, err
	}
	// Loading for uninstall must remain possible after certificate expiry.
	if !agent.ValidServer(config.Server) || !state.ValidMode(config.Mode) || len(config.DeviceID) != 64 {
		return config, dir, errors.New("invalid saved agent configuration")
	}
	return config, dir, nil
}

func hello() wire.Hello {
	hostname, _ := os.Hostname()
	username := ""
	if current, err := user.Current(); err == nil {
		username = current.Username
	}
	return wire.Hello{Hostname: hostname, Username: username, Platform: "windows", Architecture: runtime.GOARCH, Elevated: windows.GetCurrentProcessToken().IsElevated()}
}

func eventName(id string) (*uint16, error) {
	return windows.UTF16PtrFromString(`Local\ZireaelRMM-` + id)
}

func runUser(ctx context.Context, config agent.Config) error {
	attributes, err := security(false)
	if err != nil {
		return err
	}
	name, err := eventName(config.DeviceID)
	if err != nil {
		return err
	}
	event, err := windows.CreateEvent(attributes, 1, 0, name)
	if err != nil {
		if event != 0 {
			windows.CloseHandle(event)
		}
		return errors.New("agent is already running or its stop control is unavailable")
	}
	defer windows.CloseHandle(event)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	waitDone := make(chan struct{})
	go func() {
		defer close(waitDone)
		for {
			result, err := windows.WaitForSingleObject(event, 500)
			if err != nil || result == windows.WAIT_OBJECT_0 {
				cancel()
				return
			}
			if ctx.Err() != nil {
				return
			}
		}
	}()
	err = agent.Run(ctx, config, hello(), func(message string) { fmt.Println(message) }, operationHandler().Serve)
	cancel()
	<-waitDone
	return err
}

type serviceHandler struct{}

func (*serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	config, _, err := load()
	if err != nil || config.Mode != "service" {
		return true, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- agent.Run(ctx, config, hello(), nil, operationHandler().Serve) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				return true, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		}
	}
}

func uninstall() error {
	config, dir, err := load()
	if err != nil {
		return err
	}
	executable := filepath.Join(dir, installedExecutableName)
	if config.Mode == "service" {
		if !windows.GetCurrentProcessToken().IsElevated() {
			return errors.New("service removal requires an already elevated terminal")
		}
		manager, err := mgr.Connect()
		if err != nil {
			return err
		}
		defer manager.Disconnect()
		service, err := manager.OpenService(serviceName)
		if err != nil {
			return err
		}
		defer service.Close()
		current, err := service.Config()
		if err != nil {
			return err
		}
		if current.BinaryPathName != windows.EscapeArg(executable)+" service" {
			return errors.New("service points to another installation; it was not changed")
		}
		_, _ = service.Control(svc.Stop)
		deadline := time.Now().Add(20 * time.Second)
		for {
			state, err := service.Query()
			if err != nil {
				return err
			}
			if state.State == svc.Stopped {
				break
			}
			if time.Now().After(deadline) {
				return errors.New("service did not stop; files were not removed")
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err = service.Delete(); err != nil {
			return err
		}
	} else {
		if config.Mode == "user" {
			if err = removeStartup(executable); err != nil {
				return err
			}
		}
		name, err := eventName(config.DeviceID)
		if err != nil {
			return err
		}
		event, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, name)
		if err == nil {
			err = windows.SetEvent(event)
			windows.CloseHandle(event)
			if err != nil {
				return err
			}
		} else if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return err
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			handle, openErr := windows.OpenEvent(windows.SYNCHRONIZE, false, name)
			if errors.Is(openErr, windows.ERROR_FILE_NOT_FOUND) {
				break
			}
			if openErr != nil {
				return openErr
			}
			windows.CloseHandle(handle)
			if time.Now().After(deadline) {
				return errors.New("agent did not stop; identity was not removed")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	if err = os.Remove(filepath.Join(dir, configName)); err != nil {
		return err
	}
	for _, name := range []string{"desktop-engine.exe", "desktop.js", "DESKTOP-NOTICES.txt"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	// The running uninstaller executable cannot be deleted on Windows. Its identity
	// and startup entry are removed, leaving an inert file for ordinary deletion.
	fmt.Printf("Support access removed. Close this process, then delete %s. Revoke the device in the console as well.\n", dir)
	return nil
}
