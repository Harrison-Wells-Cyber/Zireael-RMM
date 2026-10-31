package bootstrap

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/agent"
)

// Package is an immutable, self-contained PS1 with a default user enrollment.
// Private support commands override Enrollment without putting it in a URL.
type Package struct {
	data   []byte
	SHA256 string
}

func (a *Artifact) PowerShell(in agent.Invite) (*Package, error) {
	script, err := installCommand(in, a.SHA256, base64.StdEncoding.EncodeToString(a.data), true)
	if err != nil {
		return nil, err
	}
	data := []byte(script + "\n")
	digest := sha256.Sum256(data)
	return &Package{data: data, SHA256: hex.EncodeToString(digest[:])}, nil
}

func (p *Package) Download(w http.ResponseWriter, r *http.Request) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Minute))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="zireael-rmm-agent.ps1"`)
	w.Header().Set("Content-Length", fmt.Sprint(len(p.data)))
	w.WriteHeader(http.StatusOK)
	if r.Method != "HEAD" {
		_, _ = w.Write(p.data)
	}
}
