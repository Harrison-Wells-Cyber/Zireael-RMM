package bootstrap

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/Harrison-Wells-Cyber/Zireael-RMM/internal/agent"
	"strings"
)

// UpdateScript is delivered only through an authenticated command operation.
// The expected hash comes over the inner TLS channel, independently of HTTPS
// inspection of the public binary download. No enrollment capability is needed.
func (a *Artifact) UpdateScript(server, id, requestID string) (string, error) {
	if a == nil || a.Version == "" || !agent.ValidServer(server) || len(id) != 64 || len(requestID) != 32 {
		return "", errors.New("versioned artifact and device identity required")
	}
	for _, s := range []string{id, requestID, a.SHA256} {
		if _, e := hex.DecodeString(s); e != nil {
			return "", errors.New("invalid update identifier")
		}
	}
	return strings.NewReplacer("%URL%", quote(server+"/agent/download"), "%HASH%", quote(a.SHA256), "%ID%", quote(id), "%REQUEST%", quote(requestID), "%RUNNER%", quote(base64.StdEncoding.EncodeToString([]byte(updateRunner)))).Replace(updateStager), nil
}

const updateStager = `$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$elevated=([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$me=Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)
$parent=Get-CimInstance Win32_Process -Filter ('ProcessId='+$me.ParentProcessId)
if (!$parent.ExecutablePath -or [IO.Path]::GetFileName($parent.ExecutablePath) -ine 'ZireaelRMM.exe') { throw 'The installed agent process could not be identified' }
$target=[IO.Path]::GetDirectoryName($parent.ExecutablePath)
$base=if ($elevated) { [Environment]::GetFolderPath('ProgramFiles') } else { [IO.Path]::GetTempPath() }
$d=Join-Path $base ('ZireaelRMM-'+[Guid]::NewGuid().ToString('N'))
$handedOff=$false
try {
 [IO.Directory]::CreateDirectory($d)|Out-Null
 $acl=New-Object Security.AccessControl.DirectorySecurity
 $acl.SetAccessRuleProtection($true,$false)
 $acl.SetOwner($identity.User)
 foreach ($sid in @($identity.User,([Security.Principal.SecurityIdentifier]'S-1-5-18'))) { $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow'))) }
 Set-Acl -LiteralPath $d -AclObject $acl
 $f=Join-Path $d 'ZireaelRMM.exe'
 $download=New-Object Net.WebClient
 try { $download.DownloadFile(%URL%,$f) } finally { $download.Dispose() }
 if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ine %HASH%) { throw 'Agent download verification failed' }
 $check=New-Object Diagnostics.ProcessStartInfo
 $check.FileName=$f;$check.Arguments='upgrade --check --expected-id '+%ID%+' --target "'+$target+'"'
 $check.UseShellExecute=$false;$check.CreateNoWindow=$true;$check.RedirectStandardOutput=$true;$check.RedirectStandardError=$true
 $p=New-Object Diagnostics.Process;$p.StartInfo=$check
 try { if (!$p.Start()) { throw 'Could not validate update target' };$out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync();if (!$p.WaitForExit(30000)) { $p.Kill();throw 'Update validation timed out' };if ($p.ExitCode -ne 0) { throw ('Update target validation failed: '+$err.Result) } } finally { $p.Dispose() }
 $config=@{stage=$d;target=$target;id=%ID%;hash=%HASH%;request=%REQUEST%;sid=$identity.User.Value;session=[Diagnostics.Process]::GetCurrentProcess().SessionId;elevated=$elevated}|ConvertTo-Json -Compress
 $data=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($config))
 $body=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(%RUNNER%))
 $body='$update=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('''+$data+'''))|ConvertFrom-Json;'+$body
 $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
 $ps=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
 $environment=[string[]]([Environment]::GetEnvironmentVariables().GetEnumerator()|ForEach-Object { [string]$_.Key+'='+[string]$_.Value })
 $startup=New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property @{CreateFlags=[uint32]0x09000000;ShowWindow=[uint16]0;WinstationDesktop='winsta0\default';EnvironmentVariables=$environment}
 $created=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=('"'+$ps+'" -NoLogo -NoProfile -NonInteractive -EncodedCommand '+$encoded);CurrentDirectory=$d;ProcessStartupInformation=$startup}
 if ($created.ReturnValue -ne 0) { throw ('Windows could not start the update helper: '+$created.ReturnValue) }
 $until=[DateTime]::UtcNow.AddSeconds(20)
 while (!(Test-Path -LiteralPath (Join-Path $d 'started'))) { if ([DateTime]::UtcNow -ge $until) { throw 'The independent update helper did not start' };Start-Sleep -Milliseconds 100 }
 $started=[IO.File]::ReadAllText((Join-Path $d 'started'))
 if ($started -ne 'ready') { throw $started }
 [IO.File]::WriteAllText((Join-Path $d 'go'),'go')
 $handedOff=$true
 Write-Output ('ZIREAEL_UPDATE_QUEUED:'+%REQUEST%)
} finally {
 if (!$handedOff -and (Test-Path -LiteralPath $d)) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
}`

// A short-lived independent helper survives shutdown of the old agent's command
// Job Object. It performs no networking, does not change its token, and has no
// persistence. The new executable validates the target again before repair.
const updateRunner = `
$ErrorActionPreference='Stop'
$result=@{request=$update.request;ok=$false;message='Update did not complete';time=[DateTime]::UtcNow.ToString('o')}
try {
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $elevated=([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
 if ($identity.User.Value -ne $update.sid -or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne $update.session -or $elevated -ne $update.elevated) { throw 'Windows launched the helper in a different security context; no update was performed' }
 [IO.File]::WriteAllText((Join-Path $update.stage 'started'),'ready')
 $until=[DateTime]::UtcNow.AddSeconds(30)
 while (!(Test-Path -LiteralPath (Join-Path $update.stage 'go'))) { if ([DateTime]::UtcNow -ge $until) { throw 'Update was cancelled before handoff' };Start-Sleep -Milliseconds 100 }
 Start-Sleep -Seconds 3
 $f=Join-Path $update.stage 'ZireaelRMM.exe'
 if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ine $update.hash) { throw 'Staged agent verification failed' }
 $info=New-Object Diagnostics.ProcessStartInfo
 $info.FileName=$f;$info.Arguments='upgrade --expected-id '+$update.id+' --target "'+$update.target+'"'
 $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $p=New-Object Diagnostics.Process;$p.StartInfo=$info
 try {
  if (!$p.Start()) { throw 'Could not start updater' }
  $out=$p.StandardOutput.ReadToEndAsync();$err=$p.StandardError.ReadToEndAsync()
  if (!$p.WaitForExit(180000)) { $p.Kill();throw 'Update timed out' }
  if ($p.ExitCode -ne 0) { throw ('Update failed: '+$err.Result) }
  $result.ok=$true;$result.message='Agent updated'
 } finally { $p.Dispose() }
} catch {
 $result.message=$_.Exception.Message
 try { if (!(Test-Path -LiteralPath (Join-Path $update.stage 'started'))) { [IO.File]::WriteAllText((Join-Path $update.stage 'started'),$result.message) } } catch {}
} finally {
 if ($result.message.Length -gt 2048) { $result.message=$result.message.Substring(0,2048) }
 try { [IO.File]::WriteAllText((Join-Path $update.target 'update-result.json'),($result|ConvertTo-Json -Compress)) } catch {}
 for ($n=0;$n -lt 40;$n++) { try { Remove-Item -LiteralPath $update.stage -Recurse -Force -ErrorAction Stop;break } catch { Start-Sleep -Milliseconds 250 } }
}`
