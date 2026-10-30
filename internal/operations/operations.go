package operations

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/wire"
)

type Runner func(context.Context, string, io.Writer) (int, error)
type Desktop func(context.Context, net.Conn) error
type Handler struct {
	Command Runner
	Desktop Desktop
}

func (h Handler) Serve(ctx context.Context, conn net.Conn) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	var request wire.Operation
	if wire.Read(conn, &request) != nil || request.Validate() != nil {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Minute))
	switch request.Kind {
	case "command":
		h.command(ctx, conn, request)
	case "upload":
		upload(conn, request)
	case "download":
		download(conn, request)
	case "desktop":
		if h.Desktop == nil {
			failure(conn, errors.New("desktop engine unavailable"))
			return
		}
		// The platform adapter sends its ready reply only after its engine starts.
		if err := h.Desktop(ctx, conn); err != nil {
			failure(conn, err)
		}
	}
}
func failure(w io.Writer, err error) {
	_ = wire.Write(w, wire.Result{Type: "error", Error: err.Error()})
}

type output struct {
	mu     sync.Mutex
	conn   net.Conn
	left   int
	cancel context.CancelFunc
	err    error
}

func (o *output) Write(data []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	original := len(data)
	for len(data) > 0 {
		n := min(len(data), wire.ChunkSize, o.left)
		if n == 0 {
			o.err = errors.New("command output exceeded 4 MiB")
			o.cancel()
			return original - len(data), o.err
		}
		if err := wire.Write(o.conn, wire.Result{Type: "output", Data: data[:n]}); err != nil {
			o.err = err
			o.cancel()
			return original - len(data), err
		}
		o.left -= n
		data = data[n:]
	}
	return original, nil
}
func (h Handler) command(ctx context.Context, conn net.Conn, r wire.Operation) {
	if h.Command == nil {
		failure(conn, errors.New("command runner unavailable"))
		return
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(r.Timeout)*time.Second)
	defer cancel()
	// No client data is legal after the command request. EOF detects cancellation
	// even for a silent command; the process tree must not outlive this stream.
	readDone := make(chan struct{})
	go func() { defer close(readDone); var b [1]byte; _, _ = conn.Read(b[:]); cancel() }()
	out := &output{conn: conn, left: wire.MaxOutput, cancel: cancel}
	code, err := h.Command(ctx, r.Script, out)
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if out.err != nil {
		err = out.err
	}
	result := wire.Result{Type: "done", ExitCode: code}
	if err != nil {
		result.Error = err.Error()
	}
	_ = wire.Write(conn, result)
	_ = conn.SetReadDeadline(time.Now())
	<-readDone
}

// Accept local absolute disk paths only. Reject UNC/device namespaces and NTFS
// alternate streams, which can name devices or cause implicit SMB credentials.
func localPath(path string) bool {
	if strings.ContainsRune(path, 0) || len(path) > 4096 {
		return false
	}
	if os.PathSeparator == '\\' {
		return len(path) >= 3 && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' && (path[2] == '\\' || path[2] == '/') && !strings.Contains(path[2:], ":")
	}
	return filepath.IsAbs(path)
}
func upload(conn net.Conn, r wire.Operation) {
	if !localPath(r.Path) {
		failure(conn, errors.New("use an absolute local disk path"))
		return
	}
	// Exclusive create avoids overwriting an existing file or following its final
	// symlink. Partial uploads are removed on interruption. Parent access is still
	// governed by the agent's Windows token and the local filesystem ACLs.
	file, err := os.OpenFile(r.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		failure(conn, err)
		return
	}
	complete := false
	defer func() {
		file.Close()
		if !complete {
			_ = os.Remove(r.Path)
		}
	}()
	if wire.Write(conn, wire.Result{Type: "ready"}) != nil {
		return
	}
	if _, err = io.CopyN(file, conn, r.Size); err != nil {
		failure(conn, err)
		return
	}
	if err = file.Sync(); err != nil {
		failure(conn, err)
		return
	}
	if err = file.Close(); err != nil {
		failure(conn, err)
		return
	}
	complete = true
	_ = wire.Write(conn, wire.Result{Type: "done", Size: r.Size})
}
func download(conn net.Conn, r wire.Operation) {
	if !localPath(r.Path) {
		failure(conn, errors.New("use an absolute local disk path"))
		return
	}
	file, err := os.Open(r.Path)
	if err != nil {
		failure(conn, err)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		failure(conn, err)
		return
	}
	if !info.Mode().IsRegular() || info.Size() > wire.MaxFile {
		failure(conn, errors.New("requires a regular file no larger than 1 GiB"))
		return
	}
	if wire.Write(conn, wire.Result{Type: "ready", Size: info.Size()}) != nil {
		return
	}
	_, _ = io.CopyN(conn, file, info.Size())
}
