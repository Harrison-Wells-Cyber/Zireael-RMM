// Package winproc launches children suspended, assigns them to a kill-on-close
// Windows Job Object, then resumes them. No child code runs outside the job.
package winproc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Process struct {
	PID     uint32
	job     windows.Handle
	process windows.Handle
	once    sync.Once
	stop    func() bool
}

func Start(ctx context.Context, exe string, args []string, stdin, stdout, stderr *os.File, desktop string) (*Process, error) {
	return start(ctx, exe, args, stdin, stdout, stderr, desktop, 0)
}

// StartAsUser uses no inherited handles: Windows forbids handle inheritance
// across sessions. Desktop IPC uses an authenticated local named pipe.
func StartAsUser(ctx context.Context, exe string, args []string, token windows.Token) (*Process, error) {
	return start(ctx, exe, args, nil, nil, nil, `winsta0\default`, token)
}

func start(ctx context.Context, exe string, args []string, stdin, stdout, stderr *os.File, desktop string, token windows.Token) (*Process, error) {
	if !filepath.IsAbs(exe) {
		return nil, errors.New("absolute executable path required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	fail := true
	defer func() {
		if fail {
			windows.CloseHandle(job)
		}
	}()
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return nil, err
	}
	si := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}}
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.CREATE_UNICODE_ENVIRONMENT)
	if token == 0 {
		attrs, err := windows.NewProcThreadAttributeList(1)
		if err != nil {
			return nil, err
		}
		defer attrs.Delete()
		files := []*os.File{stdin, stdout, stderr}
		handles := make([]windows.Handle, 3)
		// Duplicate only these handles as inheritable. Do not change inheritance on
		// shared process handles, or leak unrelated files into a privileged child.
		for i, f := range files {
			if f == nil {
				return nil, errors.New("standard handles required")
			}
			if err = windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(f.Fd()), windows.CurrentProcess(), &handles[i], 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
				return nil, err
			}
			defer windows.CloseHandle(handles[i])
		}
		if err = attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
			return nil, err
		}
		si = windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Flags: windows.STARTF_USESTDHANDLES, StdInput: handles[0], StdOutput: handles[1], StdErr: handles[2]}, ProcThreadAttributeList: attrs.List()}
		flags |= windows.EXTENDED_STARTUPINFO_PRESENT
	}
	if desktop != "" {
		si.Desktop, err = windows.UTF16PtrFromString(desktop)
		if err != nil {
			return nil, err
		}
	}
	application, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return nil, err
	}
	command, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{exe}, args...)))
	if err != nil {
		return nil, err
	}
	directory, err := windows.UTF16PtrFromString(filepath.Dir(exe))
	if err != nil {
		return nil, err
	}
	var pi windows.ProcessInformation
	if token == 0 {
		err = windows.CreateProcess(application, command, nil, nil, true, flags, nil, directory, &si.StartupInfo, &pi)
	} else {
		var environment *uint16
		if err = windows.CreateEnvironmentBlock(&environment, token, false); err != nil {
			return nil, err
		}
		defer windows.DestroyEnvironmentBlock(environment)
		err = windows.CreateProcessAsUser(token, application, command, nil, nil, false, flags, environment, directory, &si.StartupInfo, &pi)
	}
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(pi.Thread)
	if err = windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Process)
		return nil, err
	}
	if _, err = windows.ResumeThread(pi.Thread); err != nil {
		windows.TerminateJobObject(job, 1)
		windows.CloseHandle(pi.Process)
		return nil, err
	}
	p := &Process{PID: pi.ProcessId, job: job, process: pi.Process}
	p.stop = context.AfterFunc(ctx, p.Kill)
	fail = false
	return p, nil
}
func (p *Process) Kill() { p.once.Do(func() { windows.CloseHandle(p.job) }) }
func (p *Process) Wait() (int, error) {
	_, err := windows.WaitForSingleObject(p.process, windows.INFINITE)
	var code uint32
	if err == nil {
		err = windows.GetExitCodeProcess(p.process, &code)
	}
	p.stop()
	p.Kill()
	windows.CloseHandle(p.process)
	return int(code), err
}
