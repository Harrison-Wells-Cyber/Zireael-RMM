package winagent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/winproc"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/wire"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

//go:embed native/desktop.js
var desktopScript []byte

//go:embed native/NOTICES.txt
var desktopNotices []byte

func installDesktop(dir string) error {
	for name, data := range map[string][]byte{"desktop-engine.exe": desktopEngine, "desktop.js": desktopScript, "DESKTOP-NOTICES.txt": desktopNotices} {
		if err := writeNew(filepath.Join(dir, name), data); err != nil {
			return err
		}
	}
	return nil
}
func verifyDesktop(dir string) error {
	if err := noReparse(dir); err != nil {
		return err
	}
	for name, want := range map[string][32]byte{"desktop-engine.exe": sha256.Sum256(desktopEngine), "desktop.js": sha256.Sum256(desktopScript)} {
		path := filepath.Join(dir, name)
		if err := noReparse(path); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		hash := sha256.New()
		n, err := io.Copy(hash, io.LimitReader(f, 16<<20))
		f.Close()
		if err != nil || n == 16<<20 || hex.EncodeToString(hash.Sum(nil)) != hex.EncodeToString(want[:]) {
			return errors.New("desktop engine or adapter integrity check failed")
		}
	}
	if sum := sha256.Sum256(desktopEngine); hex.EncodeToString(sum[:]) != engineSHA256 {
		return errors.New("embedded desktop engine checksum mismatch")
	}
	return nil
}
func desktopToken() (windows.Token, uint32, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return 0, 0, err
	}
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return 0, 0, nil
	}
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xffffffff {
		return 0, 0, errors.New("no active Windows console session")
	}
	var processToken windows.Token
	if err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &processToken); err != nil {
		return 0, 0, err
	}
	defer processToken.Close()
	name, _ := windows.UTF16PtrFromString("SeTcbPrivilege")
	privilege := windows.Tokenprivileges{PrivilegeCount: 1}
	if err = windows.LookupPrivilegeValue(nil, name, &privilege.Privileges[0].Luid); err != nil {
		return 0, 0, err
	}
	privilege.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	if err = windows.AdjustTokenPrivileges(processToken, false, &privilege, 0, nil, nil); err != nil {
		return 0, 0, err
	}
	var token windows.Token
	if err = windows.DuplicateTokenEx(processToken, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &token); err != nil {
		return 0, 0, err
	}
	if err = windows.SetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4); err != nil {
		token.Close()
		return 0, 0, err
	}
	return token, session, nil
}
func runDesktop(ctx context.Context, stream net.Conn) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	dir := filepath.Dir(executable)
	if err = verifyDesktop(dir); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return err
	}
	pipeName := `\\.\pipe\ZireaelRMM-` + hex.EncodeToString(random)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
	if !windows.GetCurrentProcessToken().IsElevated() {
		sddl += "(A;;GA;;;" + user.User.Sid.String() + ")"
	}
	listener, err := winio.ListenPipe(pipeName, &winio.PipeConfig{SecurityDescriptor: sddl, InputBufferSize: 65536, OutputBufferSize: 65536})
	if err != nil {
		return err
	}
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { listener.Close(); stream.Close() })
	defer stop()
	token, session, err := desktopToken()
	if err != nil {
		return err
	}
	if token != 0 {
		defer token.Close()
	}
	var proc *winproc.Process
	args := []string{filepath.Join(dir, "desktop.js"), pipeName}
	if token != 0 {
		proc, err = winproc.StartAsUser(ctx, filepath.Join(dir, "desktop-engine.exe"), args, token)
	} else {
		null, e := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if e != nil {
			return e
		}
		defer null.Close()
		proc, err = winproc.Start(ctx, filepath.Join(dir, "desktop-engine.exe"), args, null, null, null, "")
	}
	if err != nil {
		return err
	}
	defer proc.Kill()
	exited := make(chan struct{})
	go func() { defer close(exited); proc.Wait(); cancel() }()
	defer func() { proc.Kill(); <-exited }()
	if token != 0 {
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if windows.WTSGetActiveConsoleSessionId() != session {
						cancel()
						return
					}
				}
			}
		}()
	}
	timer := time.AfterFunc(15*time.Second, func() { listener.Close() })
	defer timer.Stop()
	var pipe net.Conn
	for {
		pipe, err = listener.Accept()
		if err != nil {
			return errors.New("desktop engine did not connect")
		}
		handle, ok := pipe.(interface{ Fd() uintptr })
		var pid uint32
		if ok && windows.GetNamedPipeClientProcessId(windows.Handle(handle.Fd()), &pid) == nil && pid == proc.PID {
			break
		}
		pipe.Close()
	}
	listener.Close()
	timer.Stop()
	defer pipe.Close()
	_ = pipe.SetReadDeadline(time.Now().Add(10 * time.Second))
	var marker [8]byte
	if _, err = io.ReadFull(pipe, marker[:]); err != nil || string(marker[:]) != "RMMKVM1\n" {
		return errors.New("desktop engine failed to initialize")
	}
	_ = pipe.SetDeadline(time.Time{})
	if err = wire.Write(stream, wire.Result{Type: "ready"}); err != nil {
		return err
	}
	stopPipe := context.AfterFunc(ctx, func() { pipe.Close() })
	defer stopPipe()
	copied := make(chan struct{})
	go func() { defer close(copied); _, _ = io.Copy(pipe, stream); cancel() }()
	_, _ = io.Copy(stream, pipe)
	cancel()
	pipe.Close()
	stream.Close()
	<-copied
	return nil
}
