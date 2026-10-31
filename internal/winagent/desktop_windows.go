package winagent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/desktop"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/winproc"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/wire"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func systemAgent() bool {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	return e == nil && u.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}
func desktopSessions() ([]desktop.Session, *uint32, error) {
	if !systemAgent() {
		var id uint32
		if e := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &id); e != nil {
			return nil, nil, e
		}
		return []desktop.Session{{ID: id, Label: "Signed-in user", Active: true}}, &id, nil
	}
	var ptr *windows.WTS_SESSION_INFO
	var count uint32
	if e := windows.WTSEnumerateSessions(0, 0, 1, &ptr, &count); e != nil {
		return nil, nil, e
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(ptr)))
	if count > 256 {
		return nil, nil, errors.New("session limit exceeded")
	}
	var result []desktop.Session
	var def *uint32
	console := windows.WTSGetActiveConsoleSessionId()
	for _, s := range unsafe.Slice(ptr, int(count)) {
		if s.SessionID == 0 || s.State != windows.WTSActive {
			continue
		}
		if len(result) == 16 {
			break
		}
		label := windows.UTF16PtrToString(s.WindowStationName)
		result = append(result, desktop.Session{ID: s.SessionID, Label: label, Active: true})
		if s.SessionID == console {
			id := s.SessionID
			def = &id
		}
	}
	if len(result) == 1 {
		id := result[0].ID
		def = &id
	}
	return result, def, nil
}
func sessionToken(id uint32, elevated bool) (windows.Token, error) {
	if !systemAgent() {
		return 0, nil
	}
	var processToken windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_ADJUST_PRIVILEGES, &processToken); err != nil {
		return 0, err
	}
	defer processToken.Close()
	name, _ := windows.UTF16PtrFromString("SeTcbPrivilege")
	priv := windows.Tokenprivileges{PrivilegeCount: 1}
	if err := windows.LookupPrivilegeValue(nil, name, &priv.Privileges[0].Luid); err != nil {
		return 0, err
	}
	priv.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	if err := windows.AdjustTokenPrivileges(processToken, false, &priv, 0, nil, nil); err != nil {
		return 0, err
	}

	if !elevated {
		var token windows.Token
		e := windows.WTSQueryUserToken(id, &token)
		return token, e
	}
	var token windows.Token
	e := windows.DuplicateTokenEx(processToken, windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &token)
	if e != nil {
		return 0, e
	}
	if e = windows.SetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&id)), 4); e != nil {
		token.Close()
		return 0, e
	}
	return token, nil
}
func desktopFailure(stream net.Conn, code, msg string) error {
	stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_ = desktop.Write(stream, desktop.Packet(desktop.Control{Type: "status", State: "error", Code: code, Message: msg}))
	return errors.New(code)
}
func runDesktop(ctx context.Context, stream net.Conn) error {
	if e := wire.Write(stream, wire.Result{Type: "ready"}); e != nil {
		return e
	}
	sessions, def, e := desktopSessions()
	if e != nil {
		return desktopFailure(stream, "desktop_unavailable", "Windows sessions could not be enumerated.")
	}
	if len(sessions) == 0 {
		return desktopFailure(stream, "no_interactive_session", "No signed-in interactive session is available.")
	}
	if e = desktop.Write(stream, desktop.Packet(desktop.Control{Type: "hello", Protocol: 2, Sessions: sessions, DefaultSession: def, ElevatedAvailable: systemAgent()})); e != nil {
		return e
	}
	stream.SetReadDeadline(time.Now().Add(60 * time.Second))
	p, e := desktop.Read(stream, true)
	if e != nil {
		return e
	}
	start, e := desktop.ParseControl(p[desktop.HeaderSize:], true)
	if e != nil || start.Type != "start" {
		return desktop.ErrProtocol
	}
	sessions, _, e = desktopSessions()
	if e != nil {
		return e
	}
	found := false
	for _, s := range sessions {
		if s.ID == start.SessionID {
			found = true
		}
	}
	if !found {
		return desktopFailure(stream, "no_interactive_session", "The selected session is no longer available.")
	}
	if start.Privilege == "elevated" && !systemAgent() {
		return desktopFailure(stream, "access_denied", "Elevated control requires a service installation.")
	}
	token, e := sessionToken(start.SessionID, start.Privilege == "elevated")
	if e != nil {
		return desktopFailure(stream, "access_denied", "Windows could not open the selected session.")
	}
	if token != 0 {
		defer token.Close()
	}
	executable, e := os.Executable()
	if e != nil {
		return e
	}
	if systemAgent() {
		if e = desktopReadAccess(filepath.Dir(executable)); e != nil {
			return desktopFailure(stream, "worker_failed", "Windows could not grant worker read access.")
		}
	}
	random := make([]byte, 32)
	if _, e = rand.Read(random); e != nil {
		return e
	}
	name := `\\.\pipe\ZireaelRMM-Desktop-` + hex.EncodeToString(random)
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return e
	}
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;" + u.User.Sid.String() + ")"
	if token != 0 {
		t, e := token.GetTokenUser()
		if e != nil {
			return e
		}
		sddl += "(A;;GA;;;" + t.User.Sid.String() + ")"
	}
	listener, e := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: sddl, InputBufferSize: 65536, OutputBufferSize: 65536})
	if e != nil {
		return e
	}
	defer listener.Close()
	// Allow the child a short graceful release after the operation is cancelled.
	workerCtx, kill := context.WithTimeout(context.Background(), 30*time.Minute)
	defer kill()
	args := []string{"desktop-worker", name, strconv.Itoa(os.Getpid())}
	var proc *winproc.Process
	if token != 0 {
		proc, e = winproc.StartAsUser(workerCtx, executable, args, token)
	} else {
		null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer null.Close()
		proc, e = winproc.Start(workerCtx, executable, args, null, null, null, `winsta0\default`)
	}
	if e != nil {
		return desktopFailure(stream, "worker_failed", "Windows could not start the desktop worker.")
	}
	exited := make(chan struct{})
	go func() { defer close(exited); proc.Wait(); listener.Close() }()
	defer func() {
		select {
		case <-exited:
		case <-time.After(300 * time.Millisecond):
			kill()
			<-exited
		}
	}()
	stop := context.AfterFunc(ctx, func() { listener.Close(); stream.Close() })
	defer stop()
	timer := time.AfterFunc(10*time.Second, func() { listener.Close() })
	defer timer.Stop()
	var pipe net.Conn
	for {
		pipe, e = listener.Accept()
		if e != nil {
			return desktopFailure(stream, "worker_failed", "The desktop worker did not initialize.")
		}
		f, ok := pipe.(interface{ Fd() uintptr })
		var pid uint32
		if ok && windows.GetNamedPipeClientProcessId(windows.Handle(f.Fd()), &pid) == nil && pid == proc.PID {
			break
		}
		pipe.Close()
	}
	listener.Close()
	timer.Stop()
	defer pipe.Close()
	watchCtx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-ticker.C:
				if systemAgent() {
					current, _, err := desktopSessions()
					exists := false
					for _, s := range current {
						if s.ID == start.SessionID {
							exists = true
						}
					}
					if err != nil || !exists {
						pipe.Close()
						stream.Close()
						return
					}
				}
			}
		}
	}()
	defer func() { stopWatch(); <-watcherDone }()
	pipe.SetDeadline(time.Now().Add(10 * time.Second))
	var marker [8]byte
	if _, e = io.ReadFull(pipe, marker[:]); e != nil || string(marker[:]) != "ZRD2IPC\n" {
		return errors.New("invalid worker handshake")
	}
	if e = desktop.Write(pipe, desktop.Packet(start)); e != nil {
		return e
	}
	pipe.SetDeadline(time.Time{})
	stream.SetReadDeadline(time.Time{})
	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	closePipe := context.AfterFunc(relayCtx, func() { pipe.Close(); stream.Close() })
	defer closePipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer cancel()
		for {
			p, e := desktop.Read(stream, true)
			if e != nil {
				return
			}
			pipe.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if desktop.Write(pipe, p) != nil {
				return
			}
		}
	}()
	defer func() { cancel(); pipe.Close(); stream.Close(); <-done }()
	initialized := false
	firstFrameDeadline := time.Now().Add(15 * time.Second)
	for {
		deadline := firstFrameDeadline
		if initialized {
			deadline = time.Now().Add(20 * time.Second)
		}
		pipe.SetReadDeadline(deadline)
		p, e := desktop.Read(pipe, false)
		if e != nil {
			if timeout, ok := e.(net.Error); ok && timeout.Timeout() {
				return desktopFailure(stream, "worker_stalled", "Desktop capture stopped responding.")
			}
			return e
		}
		if p[4] == 2 {
			initialized = true
		} else if c, err := desktop.ParseControl(p[desktop.HeaderSize:], false); err == nil && c.State == "paused" {
			initialized = true
		}
		stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if e = desktop.Write(stream, p); e != nil {
			return e
		}
	}
}
func desktopWorker(args []string) error {
	if len(args) != 2 || !strings.HasPrefix(args[0], `\\.\pipe\ZireaelRMM-Desktop-`) || len(args[0]) != len(`\\.\pipe\ZireaelRMM-Desktop-`)+64 {
		return errors.New("invalid worker arguments")
	}
	if _, e := hex.DecodeString(strings.TrimPrefix(args[0], `\\.\pipe\ZireaelRMM-Desktop-`)); e != nil {
		return e
	}
	parent, e := strconv.ParseUint(args[1], 10, 32)
	if e != nil || parent == 0 {
		return errors.New("invalid parent")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	pipe, e := winio.DialPipeContext(ctx, args[0])
	if e != nil {
		return e
	}
	defer pipe.Close()
	f, ok := pipe.(interface{ Fd() uintptr })
	var pid uint32
	if !ok || windows.GetNamedPipeServerProcessId(windows.Handle(f.Fd()), &pid) != nil || pid != uint32(parent) {
		return errors.New("worker parent mismatch")
	}
	pipe.SetDeadline(time.Now().Add(10 * time.Second))
	if _, e = io.WriteString(pipe, "ZRD2IPC\n"); e != nil {
		return e
	}
	p, e := desktop.Read(pipe, true)
	if e != nil {
		return e
	}
	start, e := desktop.ParseControl(p[desktop.HeaderSize:], true)
	if e != nil || start.Type != "start" {
		return desktop.ErrProtocol
	}
	pipe.SetDeadline(time.Time{})
	desktop.PrepareThread()
	defer runtime.UnlockOSThread()
	var session uint32
	if windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session) != nil || session != start.SessionID {
		return fmt.Errorf("worker session mismatch")
	}
	return desktop.Serve(ctx, pipe, start, desktop.NewWindowsBackend())
}
