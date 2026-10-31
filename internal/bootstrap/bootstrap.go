// Package bootstrap generates one-paste installers with verification in the
// trusted pasted command, before any downloaded code is run.
package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/agent"
)

type Artifact struct {
	data         []byte
	SHA256       string
	Architecture string
}

func Load(path string) (*Artifact, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 100<<20 {
		return nil, errors.New("agent artifact must be a regular Windows executable under 100 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, 100<<20+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 100<<20 {
		return nil, errors.New("agent artifact too large")
	}
	parsed, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("agent must be a Windows PE executable: %w", err)
	}
	defer parsed.Close()
	arch := "amd64"
	if parsed.Machine == pe.IMAGE_FILE_MACHINE_ARM64 {
		arch = "arm64"
	} else if parsed.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		return nil, errors.New("only Windows amd64 or arm64 artifacts are supported")
	}
	hash := sha256.Sum256(data)
	return &Artifact{data: data, SHA256: hex.EncodeToString(hash[:]), Architecture: arch}, nil
}

func (a *Artifact) Download(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/vnd.microsoft.portable-executable")
	w.Header().Set("Content-Disposition", `attachment; filename="zireael-rmm-agent.exe"`)
	w.Header().Set("Content-Length", fmt.Sprint(len(a.data)))
	w.WriteHeader(http.StatusOK)
	if r.Method != "HEAD" {
		_, _ = w.Write(a.data)
	}
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func Command(in agent.Invite, digest string) (string, error) {
	return command(in, digest, false)
}

// LocalCommand installs an explicitly downloaded EXE. The file is copied into
// the same protected staging directory and checked before it is executed.
func LocalCommand(in agent.Invite, digest string) (string, error) {
	return command(in, digest, true)
}

func command(in agent.Invite, digest string, local bool) (string, error) {
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size || !agent.ValidServer(in.Server) {
		return "", errors.New("valid server and SHA-256 required")
	}
	if in.Mode != "user" && in.Mode != "service" && in.Mode != "temporary" {
		return "", errors.New("valid installation mode required")
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return "", err
	}
	config := base64.StdEncoding.EncodeToString(raw)
	// No executable first stage is fetched. All downloaded bytes are hashed here.
	elevation := ""
	if in.Mode == "service" {
		elevation = "if (-not $elevated) { throw 'Open PowerShell as administrator for service installation' }; "
	}
	prepare := ""
	stage := "Invoke-WebRequest -UseBasicParsing -Uri " + quote(in.Server+"/agent/download") + " -OutFile $f;"
	if local {
		prepare = "$source=Read-Host 'Full path to the downloaded zireael-rmm-agent.exe (without quotes)'; if ([string]::IsNullOrWhiteSpace($source)) { throw 'An EXE path is required' };"
		stage = "Copy-Item -LiteralPath $source -Destination $f -ErrorAction Stop;"
	}
	return strings.Join([]string{
		"& { $ErrorActionPreference='Stop';",
		"$elevated=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);",
		elevation,
		prepare,
		"$base=if ($elevated) { [Environment]::GetFolderPath('ProgramFiles') } else { [IO.Path]::GetTempPath() };",
		"[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12;",
		"$d=Join-Path $base ('ZireaelRMM-'+[Guid]::NewGuid().ToString('N'));",
		"[IO.Directory]::CreateDirectory($d) | Out-Null;",
		"if ($elevated) { $acl=New-Object Security.AccessControl.DirectorySecurity; $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'); Set-Acl -LiteralPath $d -AclObject $acl };",
		"$f=Join-Path $d 'ZireaelRMM.exe';",
		"try {",
		stage,
		"if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ne " + quote(digest) + ") { throw 'Agent verification failed' };",
		"$p=New-Object System.Diagnostics.Process;",
		"$p.StartInfo.FileName=$f; $p.StartInfo.Arguments=" + quote("install --mode "+in.Mode) + ";",
		"$p.StartInfo.UseShellExecute=$false; $p.StartInfo.CreateNoWindow=$true;",
		"$p.StartInfo.RedirectStandardInput=$true; $p.StartInfo.RedirectStandardOutput=$true; $p.StartInfo.RedirectStandardError=$true;",
		"try {",
		"if (-not $p.Start()) { throw 'Could not launch agent installer' };",
		"$outTask=$p.StandardOutput.ReadToEndAsync(); $errTask=$p.StandardError.ReadToEndAsync();",
		"$p.StandardInput.WriteLine(" + quote(config) + "); $p.StandardInput.Close();",
		"$p.WaitForExit();",
		"$out=$outTask.GetAwaiter().GetResult(); $err=$errTask.GetAwaiter().GetResult();",
		"if ($out) { Write-Host ($out.TrimEnd()) };",
		"if ($p.ExitCode -ne 0) { throw ('Agent installation failed: ' + $err.Trim()) };",
		"if ($err) { Write-Warning ($err.TrimEnd()) }",
		"} finally { $p.Dispose() }",
		"} finally {",
		"$removed=$false;",
		"for ($i=0; $i -lt 10; $i++) {",
		"if (-not (Test-Path -LiteralPath $d)) { $removed=$true; break };",
		"try { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction Stop; $removed=$true; break }",
		"catch { Start-Sleep -Milliseconds 250 }",
		"};",
		"if (-not $removed) { Write-Warning ('Temporary installer remains at ' + $d) }",
		"}",
		"}",
	}, " "), nil
}
