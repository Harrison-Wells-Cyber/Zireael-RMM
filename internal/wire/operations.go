package wire

import (
	"errors"
	"strings"
)

const MaxFile int64 = 1 << 30
const MaxOutput = 4 << 20
const ChunkSize = 16 << 10

type Open struct {
	Ticket string `json:"ticket"`
}
type Operation struct {
	Kind    string `json:"kind"`
	Script  string `json:"script,omitempty"`
	Timeout int    `json:"timeout,omitempty"`
	Path    string `json:"path,omitempty"`
	Size    int64  `json:"size,omitempty"`
}
type Result struct {
	Type     string `json:"type"`
	Error    string `json:"error,omitempty"`
	Data     []byte `json:"data,omitempty"`
	Size     int64  `json:"size,omitempty"`
	ExitCode int    `json:"exitCode,omitempty"`
}

func (o Operation) Validate() error {
	switch o.Kind {
	case "command":
		if len(o.Script) > 0 && len(o.Script) <= 32<<10 && o.Timeout >= 1 && o.Timeout <= 600 && o.Path == "" && o.Size == 0 {
			return nil
		}
	case "upload", "download":
		if len(o.Path) > 0 && len(o.Path) <= 4096 && !strings.ContainsRune(o.Path, 0) && o.Size >= 0 && o.Size <= MaxFile && o.Script == "" && o.Timeout == 0 && (o.Kind == "upload" || o.Size == 0) {
			return nil
		}
	case "desktop":
		if o.Script == "" && o.Path == "" && o.Size == 0 && o.Timeout == 0 {
			return nil
		}
	}
	return errors.New("invalid operation or limits exceeded")
}
