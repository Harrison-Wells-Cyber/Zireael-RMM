package winagent

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"unicode/utf16"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/operations"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/winproc"
	"golang.org/x/sys/windows"
)

func operationHandler() operations.Handler {
	return operations.Handler{Command: runPowerShell, Desktop: runDesktop}
}
func runPowerShell(ctx context.Context, script string, output io.Writer) (int, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return -1, err
	}
	// The script travels on stdin instead of a command line visible to other users.
	wrapper := `[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); $OutputEncoding=[Console]::OutputEncoding; [Console]::InputEncoding=[Console]::OutputEncoding; $ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; try { $s=[Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($s)); if (!$?) { exit 1 } } catch { [Console]::Error.WriteLine($_.ToString()); exit 1 }`
	units := utf16.Encode([]rune(wrapper))
	encoded := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(encoded[2*i:], u)
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		return -1, err
	}
	defer inR.Close()
	defer inW.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		return -1, err
	}
	defer outR.Close()
	defer outW.Close()
	proc, err := winproc.Start(ctx, filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe"), []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded)}, inR, outW, outW, "")
	if err != nil {
		return -1, err
	}
	inR.Close()
	outW.Close()
	writeDone := make(chan error, 1)
	go func() { _, e := io.WriteString(inW, script); inW.Close(); writeDone <- e }()
	copyDone := make(chan error, 1)
	go func() {
		_, e := io.Copy(output, outR)
		if e != nil {
			proc.Kill()
		}
		copyDone <- e
	}()
	code, err := proc.Wait()
	if e := <-writeDone; err == nil {
		err = e
	}
	if e := <-copyDone; err == nil {
		err = e
	}
	return code, err
}
