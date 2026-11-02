package winagent

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/installstate"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type installation struct {
	dir, mode string
	elevated  bool
}

func samePath(a, b string) bool { return strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) }
func installations() ([]installation, error) {
	user, e := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if e != nil {
		return nil, e
	}
	programs, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if e != nil {
		return nil, e
	}
	token, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return nil, e
	}
	result := []installation{{filepath.Join(user, serviceName), "user", false}, {filepath.Join(programs, serviceName+"-User-"+token.User.Sid.String()), "user", true}, {filepath.Join(programs, serviceName), "service", true}}
	for _, base := range []string{user, programs} {
		entries, e := os.ReadDir(base)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			if samePath(base, programs) && errors.Is(e, os.ErrPermission) && !windows.GetCurrentProcessToken().IsElevated() {
				continue
			}
			return nil, e
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), serviceName+"-Temporary-") {
				continue
			}
			suffix := strings.TrimPrefix(entry.Name(), serviceName+"-Temporary-")
			if len(suffix) != 16 {
				continue
			}
			if _, e := hex.DecodeString(suffix); e != nil {
				continue
			}
			dir := filepath.Join(base, entry.Name())
			if samePath(base, programs) {
				owned, e := temporaryOwnedByUser(dir, token.User.Sid)
				if e != nil {
					if errors.Is(e, os.ErrPermission) && !windows.GetCurrentProcessToken().IsElevated() {
						continue
					}
					return nil, e
				}
				if !owned {
					continue
				}
			}
			result = append(result, installation{dir, "temporary", samePath(base, programs)})
		}
	}
	return result, nil
}
func openInstallation(dir string) (*os.Root, error) {
	if e := noReparse(dir); e != nil {
		return nil, e
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		return nil, e
	}
	f, e := root.Open(".")
	if e != nil {
		root.Close()
		return nil, e
	}
	defer f.Close()
	var path [32768]uint16
	n, e := windows.GetFinalPathNameByHandle(windows.Handle(f.Fd()), &path[0], uint32(len(path)), 0)
	if e != nil || n == 0 || n >= uint32(len(path)) {
		root.Close()
		return nil, errors.New("could not verify installation directory")
	}
	actual := strings.TrimPrefix(windows.UTF16ToString(path[:n]), `\\?\`)
	if !samePath(actual, dir) {
		root.Close()
		return nil, errors.New("installation directory changed during maintenance")
	}
	return root, nil
}
func removeInstallationFiles(dir string, full bool) error {
	root, e := openInstallation(dir)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	if e = installstate.Recognized(root); e != nil {
		root.Close()
		return e
	}
	if full {
		e = installstate.CleanInstallation(root)
	} else {
		e = installstate.Clean(root)
	}
	if e != nil {
		root.Close()
		return e
	}
	root.Close()
	if e = os.Remove(dir); e != nil && !errors.Is(e, os.ErrNotExist) {
		return fmt.Errorf("some files remain in %s: %w", dir, e)
	}
	return nil
}
func stopInstallation(dir, mode string) error {
	if mode == "service" {
		manager, e := mgr.Connect()
		if e != nil {
			return e
		}
		defer manager.Disconnect()
		service, e := manager.OpenService(serviceName)
		if e != nil && !errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return e
		}
		if e == nil {
			defer service.Close()
			config, e := service.Config()
			if e != nil {
				return e
			}
			if config.BinaryPathName != windows.EscapeArg(filepath.Join(dir, installedExecutableName))+" service" {
				return errors.New("a different installation owns the Windows service")
			}
			if e = service.SetRecoveryActions(nil, 0); e != nil {
				return e
			}
			state, e := service.Query()
			if e != nil {
				return e
			}
			if state.State != svc.Stopped {
				if _, e = service.Control(svc.Stop); e != nil && !errors.Is(e, windows.ERROR_SERVICE_NOT_ACTIVE) {
					return stopOwnedProcesses(dir)
				}
			}
			deadline := time.Now().Add(20 * time.Second)
			for state.State != svc.Stopped {
				if time.Now().After(deadline) {
					return stopOwnedProcesses(dir)
				}
				time.Sleep(100 * time.Millisecond)
				state, e = service.Query()
				if e != nil {
					return e
				}
			}
		}
	} else if config, _, e := loadFrom(dir); e == nil {
		name, e := eventName(config.DeviceID)
		if e != nil {
			return e
		}
		event, e := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, name)
		if e == nil {
			e = windows.SetEvent(event)
			windows.CloseHandle(event)
			if e != nil {
				return e
			}
		} else if !errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
			return e
		}
	}
	// Older/damaged installs may lack a readable identity or stop event. Stop only
	// processes whose OS-reported executable path exactly matches this directory.
	return stopOwnedProcesses(dir)
}
func removeOne(in installation) error {
	if in.elevated && !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("open PowerShell as administrator to remove %s", in.dir)
	}
	if e := noReparse(in.dir); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if root, e := openInstallation(in.dir); e == nil {
		e = installstate.Recognized(root)
		root.Close()
		if e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e := stopInstallation(in.dir, in.mode); e != nil {
		return e
	}
	if in.mode == "service" {
		manager, e := mgr.Connect()
		if e != nil {
			return e
		}
		defer manager.Disconnect()
		service, e := manager.OpenService(serviceName)
		if e == nil {
			e = service.Delete()
			service.Close()
			if e != nil {
				return e
			}
		} else if !errors.Is(e, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return e
		}
		deadline := time.Now().Add(15 * time.Second)
		for {
			probe, err := manager.OpenService(serviceName)
			if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
				break
			}
			if err == nil {
				probe.Close()
			} else if !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
				return err
			}
			if time.Now().After(deadline) {
				return errors.New("Windows is still removing the service; close the Services window and retry")
			}
			time.Sleep(100 * time.Millisecond)
		}
	} else if in.mode == "user" {
		key, e := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
		matching := errors.Is(e, registry.ErrNotExist)
		if e == nil {
			value, _, vErr := key.GetStringValue(serviceName)
			key.Close()
			matching = errors.Is(vErr, registry.ErrNotExist) || vErr == nil && value == windows.EscapeArg(filepath.Join(in.dir, installedExecutableName))+" run"
		} else if !matching {
			return e
		}
		if matching {
			if e = removeStartup(filepath.Join(in.dir, installedExecutableName)); e != nil {
				return e
			}
		}
	}
	if e := removeUninstallEntry(in.dir, in.mode); e != nil {
		return e
	}
	return removeInstallationFiles(in.dir, true)
}
func removeInstallations(mode, target string) error {
	entries, e := installations()
	if e != nil {
		return e
	}
	found := false
	var selected []installation
	for _, in := range entries {
		if target != "" && !samePath(in.dir, target) || mode != "" && in.mode != mode {
			continue
		}
		if _, e := os.Lstat(in.dir); errors.Is(e, os.ErrNotExist) {
			registered, err := hasRegistration(in)
			if err != nil {
				return err
			}
			if !registered {
				continue
			}
		} else if e != nil {
			return e
		}
		if in.elevated && !windows.GetCurrentProcessToken().IsElevated() {
			return fmt.Errorf("open PowerShell as administrator to remove %s", in.dir)
		}
		selected = append(selected, in)
	}
	for _, in := range selected {
		found = true
		if e = removeOne(in); e != nil {
			return e
		}
	}
	if target != "" && !found {
		return errors.New("installation was not found in a supported location")
	}
	// Clear orphaned user startup state only when it no longer points to a file.
	if mode != "service" && target == "" {
		if e = removeOrphanedStartup(); e != nil {
			return e
		}
	}
	return nil
}
func uninstall(args []string) error {
	f := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	all := f.Bool("all", false, "remove this user's installations and any accessible service installation")
	target := f.String("target", "", "remove a specific registered installation")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || *all && *target != "" {
		return errors.New("invalid uninstall arguments")
	}
	current, e := os.Executable()
	if e != nil {
		return e
	}
	entries, e := installations()
	if e != nil {
		return e
	}
	for _, in := range entries {
		if samePath(current, filepath.Join(in.dir, installedExecutableName)) && (*target == "" || samePath(in.dir, *target)) {
			return launchUninstaller(in.dir, in.mode, *all)
		}
	}
	if !*all && *target == "" {
		*all = true
	}
	if *target != "" && samePath(filepath.Dir(current), *target) {
		return errors.New("uninstall must run from the maintenance launcher")
	}
	if e = removeInstallations("", *target); e != nil {
		return e
	}
	if *all {
		if e = cleanupStaging(); e != nil {
			return e
		}
	}
	fmt.Println("Zireael-RMM removed. This computer will no longer connect.")
	return nil
}
func removeOrphanedStartup() error {
	key, e := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if errors.Is(e, registry.ErrNotExist) {
		return removeStartup("")
	}
	if e != nil {
		return e
	}
	defer key.Close()
	value, _, e := key.GetStringValue(serviceName)
	if errors.Is(e, registry.ErrNotExist) {
		return removeStartup("")
	}
	if e != nil {
		return e
	}
	args, e := windows.DecomposeCommandLine(value)
	if e != nil || len(args) != 2 || args[1] != "run" {
		return errors.New("unrecognized Zireael-RMM startup entry")
	}
	entries, e := installations()
	if e != nil {
		return e
	}
	for _, in := range entries {
		if in.mode == "user" && samePath(args[0], filepath.Join(in.dir, installedExecutableName)) {
			if _, e := os.Lstat(args[0]); errors.Is(e, os.ErrNotExist) {
				return removeStartup(args[0])
			}
			return nil
		}
	}
	return errors.New("startup entry points outside known installation locations")
}

func hasRegistration(in installation) (bool, error) {
	hive, path := uninstallRegistry(in.dir, in.mode)
	key, e := registry.OpenKey(hive, path, registry.QUERY_VALUE)
	if e == nil {
		value, _, err := key.GetStringValue("InstallLocation")
		if errors.Is(err, registry.ErrNotExist) {
			owned, ownErr := ownsUninstallKey(key, in.dir)
			key.Close()
			if ownErr != nil {
				return false, ownErr
			}
			if owned && (in.mode == "service" || !in.elevated) {
				return true, nil
			}
		} else {
			key.Close()
			if err != nil {
				return false, err
			}
			if samePath(value, in.dir) {
				return true, nil
			}
		}
	} else if !errors.Is(e, registry.ErrNotExist) {
		return false, e
	}
	if in.mode == "service" {
		key, e = registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+serviceName, registry.QUERY_VALUE)
		if errors.Is(e, registry.ErrNotExist) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		value, _, err := key.GetStringValue("ImagePath")
		key.Close()
		if err != nil {
			return false, err
		}
		if value != windows.EscapeArg(filepath.Join(in.dir, installedExecutableName))+" service" {
			return false, errors.New("another installation owns the service registration")
		}
		return true, nil
	}
	return false, nil
}
func cleanupStaging() error {
	current, e := os.Executable()
	if e != nil {
		return e
	}
	bases := []string{os.TempDir()}
	local, e := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if e != nil {
		return e
	}
	temp := filepath.Join(local, "Temp")
	if !samePath(temp, os.TempDir()) {
		bases = append(bases, temp)
	}
	if entries, err := os.ReadDir(temp); err == nil {
		for _, entry := range entries {
			if entry.Name() == "" || len(entry.Name()) > 4 {
				continue
			}
			digits := true
			for _, r := range entry.Name() {
				if r < '0' || r > '9' {
					digits = false
					break
				}
			}
			if digits && entry.IsDir() {
				path := filepath.Join(temp, entry.Name())
				if !samePath(path, os.TempDir()) {
					bases = append(bases, path)
				}
			}
		}
	}

	if windows.GetCurrentProcessToken().IsElevated() {
		programs, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
		if e != nil {
			return e
		}
		bases = append(bases, programs)
	}
	for _, base := range bases {
		if e = noReparse(base); e != nil {
			return e
		}
		entries, e := os.ReadDir(base)
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
				continue
			}
			if !strings.HasPrefix(entry.Name(), serviceName+"-") {
				continue
			}
			suffix := strings.TrimPrefix(entry.Name(), serviceName+"-")
			if len(suffix) != 32 {
				continue
			}
			if _, e = hex.DecodeString(suffix); e != nil {
				continue
			}
			dir := filepath.Join(base, entry.Name())
			if samePath(dir, filepath.Dir(current)) {
				continue
			}
			// Only this application's GUID staging directories are eligible; the root
			// is pinned before removing contents, so links cannot escape it.
			if e = removeInstallationFiles(dir, true); e != nil {
				if errors.Is(e, installstate.ErrUnrecognized) {
					continue
				}
				return e
			}
		}
	}
	return nil
}

func temporaryOwnedByUser(dir string, sid *windows.SID) (bool, error) {
	if e := noReparse(dir); e != nil {
		return false, e
	}
	descriptor, e := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return false, e
	}
	acl, _, e := descriptor.DACL()
	if e != nil {
		return false, e
	}
	if acl == nil {
		return false, nil
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if e = windows.GetAce(acl, i, &ace); e != nil {
			return false, e
		}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			user := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if user.Equals(sid) {
				return true, nil
			}
		}
	}
	return false, nil
}
