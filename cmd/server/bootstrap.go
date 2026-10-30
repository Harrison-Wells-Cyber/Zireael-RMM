package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/state"
)

func bootstrapOwner(s *state.Store, dir string, ifNeeded, showToken bool, out io.Writer) error {
	if ifNeeded {
		owner, err := s.Owner()
		if err != nil {
			return err
		}
		if len(owner.Credentials) != 0 {
			_, err = fmt.Fprintln(out, "Owner already configured. Sign in with your existing passkey.")
			return err
		}
	}
	token, err := s.NewSetup(time.Now())
	if err != nil {
		return fmt.Errorf("create setup token: %w (bootstrap is disabled after owner registration)", err)
	}
	path := filepath.Join(dir, "setup-token.txt")
	// Replace atomically; never follow a pre-existing token-file symlink.
	tmp, err := os.CreateTemp(dir, ".setup-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.WriteString(token + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if showToken {
		_, err = fmt.Fprintf(out, "First-time setup token: %s\nOpen /admin and use this token within 15 minutes to create your first passkey.\n", token)
	} else {
		_, err = fmt.Fprintf(out, "Setup token written to %s (expires in 15 minutes). Paste it into /admin.\n", path)
	}
	return err
}
