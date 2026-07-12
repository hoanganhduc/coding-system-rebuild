@echo off
REM ===========================================================================
REM  setup-grok-proxy-windows.bat
REM  Run on the Windows PC (desktop-bff6hdq). Enables the built-in OpenSSH
REM  Server and authorizes the openclaw VM's key so the VM can open a SOCKS
REM  tunnel out through this PC over Tailscale (grok-proxy, Option A).
REM  Double-click it (it will ask for Administrator rights).
REM ===========================================================================
setlocal

REM ---- self-elevate to Administrator ----
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting Administrator privileges...
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
  exit /b
)

set "PUBKEY=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbJ9Q7hJ+Kj3nj0jDvmi4AHBTMuAaHieDJpalbf/ixp grokproxy-openclaw-vm"

echo.
echo === grok-proxy: Windows setup ===
echo.

echo [1/5] Installing OpenSSH Server (if missing)...
powershell -NoProfile -Command "if ((Get-WindowsCapability -Online -Name 'OpenSSH.Server*').State -ne 'Installed') { Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null }"

echo [2/5] Starting sshd and setting it to auto-start...
powershell -NoProfile -Command "Set-Service -Name sshd -StartupType Automatic; Start-Service sshd"

echo [3/5] Allowing SSH from the tailnet (100.64.0.0/10) through the firewall...
powershell -NoProfile -Command "if (-not (Get-NetFirewallRule -Name 'grok-proxy-sshd' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -Name 'grok-proxy-sshd' -DisplayName 'grok-proxy SSH (Tailnet)' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -RemoteAddress 100.64.0.0/10 | Out-Null }"

echo [4/5] Authorizing the openclaw VM key (restricted: forwarding-only, no shell)...
REM Windows OpenSSH uses administrators_authorized_keys for admin accounts and
REM %USERPROFILE%\.ssh\authorized_keys for standard accounts. Cover both, and lock the key
REM to forwarding-only (no shell/PTY) with a forced command so a stolen key cannot run
REM commands on this PC. permitopen limits the tunnel to the hosts grok dials (socks5h passes
REM hostnames, so the match is by name). Double-quotes in the options are built with [char]34
REM so there is nothing for the batch layer to escape.
powershell -NoProfile -Command ^
  "$k='%PUBKEY%';" ^
  "$body='AAAAC3NzaC1lZDI1NTE5AAAAILbJ9Q7hJ+Kj3nj0jDvmi4AHBTMuAaHieDJpalbf/ixp';" ^
  "$q=[char]34;" ^
  "$opts='restrict,port-forwarding,command='+$q+'exit'+$q+',permitopen='+$q+'cli-chat-proxy.grok.com:443'+$q+',permitopen='+$q+'auth.x.ai:443'+$q+',permitopen='+$q+'api.ipify.org:443'+$q+',permitopen='+$q+'ipinfo.io:443'+$q;" ^
  "$line=$opts+' '+$k;" ^
  "$admins=Join-Path $env:ProgramData 'ssh\administrators_authorized_keys';" ^
  "$user=Join-Path $env:USERPROFILE '.ssh\authorized_keys';" ^
  "foreach($f in @($admins,$user)){ New-Item -ItemType Directory -Force -Path (Split-Path $f) | Out-Null; if(Test-Path $f){ $kept=@(Get-Content $f | Where-Object { $_ -notlike ('*'+$body+'*') }) } else { $kept=@() }; ($kept + $line) | Set-Content -Path $f -Encoding ascii };" ^
  "icacls $admins /inheritance:r /grant 'SYSTEM:F' /grant 'Administrators:F' | Out-Null"

echo [5/5] Done.
echo.
echo   Put these in hosts.conf on the openclaw VM, and pin the SSH host key below:
REM Do the whole thing inside PowerShell so there is no batch-level pipe to escape.
REM Also print the ed25519 host public key as a known_hosts line (keyed by the tailnet IP)
REM so egress.sh (StrictHostKeyChecking=yes) trusts this PC without a TOFU prompt.
powershell -NoProfile -Command ^
  "$ts=Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe';" ^
  "$ip=(& $ts ip -4 | Select-Object -First 1);" ^
  "Write-Host ('    windows      ' + $ip + '   ' + $env:USERNAME + '   22');" ^
  "Write-Host '';" ^
  "Write-Host '  Add this line to the VM known_hosts next to egress.sh:';" ^
  "$hk=Join-Path $env:ProgramData 'ssh\ssh_host_ed25519_key.pub';" ^
  "if(Test-Path $hk){ $p=((Get-Content $hk) -split ' '); Write-Host ('    ' + $ip + ' ' + $p[0] + ' ' + $p[1]) } else { Write-Host '    ed25519 host key not found under ProgramData\ssh' }"
echo.
echo   For best security, have the VM log in as a STANDARD non-admin Windows account.
echo   Admin logins use administrators_authorized_keys and ignore the per-user file; the
echo   key is already restricted to forwarding-only with no shell on this PC either way.
echo.
echo   Tip: keep this PC awake while using grok (Settings ^> Power ^> never sleep),
echo        it must stay on to relay the connection.
echo.
pause
