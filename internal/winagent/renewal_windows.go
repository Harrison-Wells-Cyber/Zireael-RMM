package winagent

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/agent"
)

func saveRenewedIdentity(config agent.Config) error {
	if e := config.Validate(); e != nil {
		return e
	}
	release, e := maintenanceLock()
	if e != nil {
		return e
	}
	defer release()
	current, dir, e := load()
	if e != nil {
		return e
	}
	if current.DeviceID != config.DeviceID || current.Server != config.Server || current.Mode != config.Mode || string(current.PrivateKey) != string(config.PrivateKey) || string(current.CA) != string(config.CA) {
		return errors.New("installed identity changed during renewal")
	}
	root, e := openInstallation(dir)
	if e != nil {
		return e
	}
	defer root.Close()
	raw, e := json.Marshal(config)
	if e != nil {
		return e
	}
	protected, e := protect(raw, config.Mode == "service")
	if e != nil {
		return e
	}
	name := configName + ".new"
	// A crashed prior write is safe to discard inside the pinned installation.
	if e = root.Remove(name); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	f, e := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer root.Remove(name)
	if _, e = f.Write(protected); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	// The pinned root keeps replacement within the validated installation.
	return root.Rename(name, configName)
}
