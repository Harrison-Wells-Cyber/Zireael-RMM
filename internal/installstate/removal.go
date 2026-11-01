package installstate

import "strings"

func quotePS(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func RemovalScript(executable, arguments, digest string) string {
	return strings.Join([]string{
		"$ErrorActionPreference='Stop';",
		"$elevated=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);",
		"$base=if ($elevated) { [Environment]::GetFolderPath('ProgramFiles') } else { [IO.Path]::GetTempPath() };",
		"$d=Join-Path $base ('ZireaelRMM-'+[Guid]::NewGuid().ToString('N')); [IO.Directory]::CreateDirectory($d) | Out-Null;",
		"try {",
		"if ($elevated) { $acl=New-Object Security.AccessControl.DirectorySecurity; $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'); Set-Acl -LiteralPath $d -AclObject $acl };",
		"$f=Join-Path $d 'ZireaelRMM.exe'; Copy-Item -LiteralPath " + quotePS(executable) + " -Destination $f;",
		"if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -ne " + quotePS(digest) + ") { throw 'Uninstaller verification failed' };",
		"$p=New-Object System.Diagnostics.Process; $p.StartInfo.FileName=$f; $p.StartInfo.Arguments=" + quotePS(arguments) + ";",
		"$p.StartInfo.UseShellExecute=$false; $p.StartInfo.CreateNoWindow=$true;",
		"try { if (-not $p.Start()) { throw 'Could not start uninstaller' }; $p.WaitForExit(); if ($p.ExitCode -ne 0) { throw 'Uninstall did not complete' } } finally { $p.Dispose() };",
		"Write-Host 'Zireael-RMM removed.'",
		"} catch { Write-Host $_; Read-Host 'Press Enter to close' | Out-Null; exit 1 }",
		"finally { for ($i=0; $i -lt 40; $i++) { try { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction Stop; break } catch { Start-Sleep -Milliseconds 250 } } }",
	}, " ")
}
