// Package installstate contains bounded filesystem transactions shared by the
// Windows lifecycle code and portable regression tests.
package installstate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/agent"
)

const Executable = "ZireaelRMM.exe"
const Fresh = Executable + ".new"
const Previous = Executable + ".previous"

var Files = []string{Executable, "identity.dpapi", "desktop-engine.exe", "desktop.js", "DESKTOP-NOTICES.txt", "uninstall.ps1", Previous, Fresh}

func StartupEnabled(state []byte) bool {
	return len(state) >= 12 && bytes.Equal(state[1:4], []byte{0, 0, 0}) && (state[0] == 0 || state[0] == 2 || state[0] == 6)
}
func Matching(config agent.Config, invite agent.Invite) bool {
	return config.Mode == invite.Mode && config.Server == invite.Server && bytes.Equal(config.CA, invite.CA)
}
func retry(fn func() error) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		e := fn()
		if e == nil {
			return nil
		}
		if errors.Is(e, os.ErrNotExist) {
			return e
		}
		if time.Now().After(deadline) {
			return e
		}
		time.Sleep(100 * time.Millisecond)
	}
}
func remove(root *os.Root, name string) error {
	return retry(func() error {
		e := root.Remove(name)
		if errors.Is(e, os.ErrNotExist) {
			return nil
		}
		return e
	})
}
func Clean(root *os.Root) error {
	for _, name := range Files {
		if e := remove(root, name); e != nil {
			return fmt.Errorf("remove %s: %w", name, e)
		}
	}
	return nil
}

// Upgrade retains the identity and restores the previous executable when local
// activation fails. All callbacks run synchronously under the maintenance lock.
func Upgrade(root *os.Root, data []byte, stop, activate, restore func() error) (err error) {
	if _, e := root.Lstat(Executable); errors.Is(e, os.ErrNotExist) {
		if _, e = root.Lstat(Previous); e != nil {
			return fmt.Errorf("old executable is missing; use clean replacement: %w", e)
		}
		if e = root.Rename(Previous, Executable); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	if e := remove(root, Fresh); e != nil {
		return e
	}
	f, e := root.OpenFile(Fresh, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = io.Copy(f, bytes.NewReader(data))
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		root.Remove(Fresh)
		return e
	}
	if e = stop(); e != nil {
		root.Remove(Fresh)
		return e
	}
	moved := false
	activated := false
	defer func() {
		if err == nil || activated {
			return
		}
		stopErr := stop()
		if stopErr != nil {
			err = errors.Join(err, fmt.Errorf("stop failed update: %w", stopErr))
			return
		}
		if moved {
			if e := remove(root, Executable); e != nil {
				err = errors.Join(err, e)
				return
			}
			if e := root.Rename(Previous, Executable); e != nil {
				err = errors.Join(err, e)
				return
			}
		}
		_ = root.Remove(Fresh)
		if e := restore(); e != nil {
			err = errors.Join(err, fmt.Errorf("restore previous installation: %w", e))
		}
	}()
	if e = remove(root, Previous); e != nil {
		return e
	}
	if e = retry(func() error { return root.Rename(Executable, Previous) }); e != nil {
		return e
	}
	moved = true
	if e = root.Rename(Fresh, Executable); e != nil {
		return e
	}
	if e = activate(); e != nil {
		return e
	}
	activated = true
	// Activation succeeded. A leftover backup is cleanup work, not rollback.
	if e = remove(root, Previous); e != nil {
		return fmt.Errorf("updated successfully but previous executable remains: %w", e)
	}
	return nil
}

// CleanInstallation removes an application's dedicated directory contents. The
// caller must first verify and pin the installation root; links cannot escape it.
func CleanInstallation(root *os.Root) error {
	f, e := root.Open(".")
	if e != nil {
		return e
	}
	entries, e := f.ReadDir(-1)
	f.Close()
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if e = retry(func() error { return root.RemoveAll(entry.Name()) }); e != nil {
			return e
		}
	}
	return nil
}

var ErrUnrecognized = errors.New("directory has no recognized Zireael-RMM files; its contents were left untouched")

func Recognized(root *os.Root) error {
	for _, name := range Files {
		if _, e := root.Lstat(name); e == nil {
			return nil
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	f, e := root.Open(".")
	if e != nil {
		return e
	}
	entries, e := f.ReadDir(1)
	f.Close()
	if errors.Is(e, io.EOF) && len(entries) == 0 {
		return nil
	}
	if e != nil && !errors.Is(e, io.EOF) {
		return e
	}
	return ErrUnrecognized
}
