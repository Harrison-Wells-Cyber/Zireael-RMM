package winagent

import (
	"errors"
	"flag"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/agent"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/bootstrap"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/version"
	"golang.org/x/sys/windows"
	"path/filepath"
	"runtime"
)

// upgrade is repair-only: it cannot enroll, replace an identity, select a new
// server, or choose an arbitrary directory. The remote task supplies its device ID.
func upgrade(args []string) error {
	f := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	target := f.String("target", "", "existing installation directory")
	id := f.String("expected-id", "", "expected device identity")
	check := f.Bool("check", false, "validate without changing the installation")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || !filepath.IsAbs(*target) || len(*id) != 64 {
		return errors.New("upgrade requires target and expected-id")
	}
	entries, e := installations()
	if e != nil {
		return e
	}
	var found *installation
	for _, in := range entries {
		if samePath(in.dir, *target) {
			candidate := in
			found = &candidate
			break
		}
	}
	if found == nil {
		return errors.New("unrecognized installation path")
	}
	if found.elevated && !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("existing installation requires an already elevated updater")
	}
	config, _, e := loadFrom(found.dir)
	if e != nil {
		return e
	}
	if config.DeviceID != *id || config.Mode != found.mode {
		return errors.New("update target identity or mode mismatch")
	}
	if e = config.Validate(); e != nil {
		return e
	}
	if config.Mode == "user" {
		if e = checkStartupPolicy(); e != nil {
			return e
		}
	}
	old, e := bootstrap.Load(filepath.Join(found.dir, installedExecutableName))
	if e != nil {
		return e
	}
	if old.Architecture != runtime.GOARCH {
		return errors.New("update package architecture differs from the installed agent")
	}
	if old.Version != "" && version.Compare(version.Current(), old.Version) < 0 {
		return errors.New("refusing to downgrade the installed agent")
	}
	if *check {
		return nil
	}
	return repairInstallation(found.dir, agent.Invite{Server: config.Server, CA: config.CA, Mode: config.Mode})
}
