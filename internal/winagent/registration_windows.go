package winagent

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/installstate"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/version"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
func encodedPowerShell(script string) string {
	chars := utf16.Encode([]rune(script))
	data := make([]byte, len(chars)*2)
	for i, v := range chars {
		binary.LittleEndian.PutUint16(data[i*2:], v)
	}
	return base64.StdEncoding.EncodeToString(data)
}
func uninstallCommand(dir, mode string, all ...bool) (string, error) {
	executable := filepath.Join(dir, installedExecutableName)
	data, e := os.ReadFile(executable)
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256(data)
	workerArgs := []string{"uninstall", "--target", dir}
	if len(all) > 0 && all[0] {
		workerArgs = []string{"uninstall", "--all"}
	}
	script := installstate.RemovalScript(executable, windows.ComposeCommandLine(workerArgs), hex.EncodeToString(sum[:]))
	needsElevation := mode == "service"
	programFiles, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if e != nil {
		return "", e
	}
	if samePath(filepath.Dir(dir), programFiles) {
		needsElevation = true
	}
	system, e := windows.GetSystemDirectory()
	if e != nil {
		return "", e
	}
	powershell := filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe")
	if needsElevation {
		inner := encodedPowerShell(script)
		script = "$ErrorActionPreference='Stop'; $p=Start-Process -FilePath " + psQuote(powershell) + " -ArgumentList " + psQuote("-NoLogo -NoProfile -EncodedCommand "+inner) + " -Verb RunAs -Wait -PassThru; exit $p.ExitCode"
	}
	return windows.ComposeCommandLine([]string{powershell, "-NoLogo", "-NoProfile", "-EncodedCommand", encodedPowerShell(script)}), nil
}
func uninstallRegistry(dir, mode string) (registry.Key, string) {
	hive := registry.CURRENT_USER
	if mode == "service" {
		hive = registry.LOCAL_MACHINE
	}
	name := serviceName
	if mode == "temporary" {
		name = filepath.Base(dir)
	}
	return hive, uninstallKey + `\` + name
}
func registerUninstaller(dir, mode string) (err error) {
	command, e := uninstallCommand(dir, mode)
	if e != nil {
		return e
	}
	hive, path := uninstallRegistry(dir, mode)
	key, existed, e := registry.CreateKey(hive, path, registry.QUERY_VALUE|registry.SET_VALUE)
	if e != nil {
		return e
	}
	defer func() {
		key.Close()
		if err != nil && !existed {
			_ = registry.DeleteKey(hive, path)
		}
	}()
	if existed {
		owned, e := ownsUninstallKey(key, dir)
		if e != nil {
			return e
		}
		if !owned {
			return errors.New("another installation owns the uninstall entry")
		}
	}
	if e = key.SetStringValue("InstallLocation", dir); e != nil {
		return e
	}
	label := "Zireael-RMM"
	if mode == "service" {
		label += " (service)"
	}
	if mode == "temporary" {
		label += " (temporary)"
	}
	for name, value := range map[string]string{"DisplayName": label, "Publisher": "Zireael-RMM", "DisplayVersion": version.Current(), "DisplayIcon": filepath.Join(dir, installedExecutableName) + ",0", "InstallLocation": dir, "UninstallString": command} {
		if e = key.SetStringValue(name, value); e != nil {
			return e
		}
	}
	for _, name := range []string{"NoModify", "NoRepair"} {
		if e = key.SetDWordValue(name, 1); e != nil {
			return e
		}
	}
	return nil
}
func removeUninstallEntry(dir, mode string) error {
	hive, path := uninstallRegistry(dir, mode)
	key, e := registry.OpenKey(hive, path, registry.QUERY_VALUE)
	if errors.Is(e, registry.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	owned, e := ownsUninstallKey(key, dir)
	key.Close()
	if e != nil {
		return e
	}
	if !owned {
		return nil
	}
	return registry.DeleteKey(hive, path)
}
func launchUninstaller(dir, mode string, all ...bool) error {
	command, e := uninstallCommand(dir, mode, all...)
	if e != nil {
		return e
	}
	args, e := windows.DecomposeCommandLine(command)
	if e != nil {
		return e
	}
	child := exec.Command(args[0], args[1:]...)
	if e = child.Start(); e != nil {
		return e
	}
	_ = child.Process.Release()
	fmt.Println("Uninstall started. Follow the uninstall window to completion.")
	return nil
}

func ownsUninstallKey(key registry.Key, dir string) (bool, error) {
	location, _, e := key.GetStringValue("InstallLocation")
	if e == nil {
		return samePath(location, dir), nil
	}
	if !errors.Is(e, registry.ErrNotExist) {
		return false, e
	}
	names, e := key.ReadValueNames(-1)
	if e != nil {
		return false, e
	}
	if len(names) == 0 {
		return true, nil
	}
	label, _, e := key.GetStringValue("DisplayName")
	if e != nil {
		return false, e
	}
	return strings.HasPrefix(label, "Zireael-RMM"), nil
}
