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

echo [4/5] Authorizing the openclaw VM key...
REM Windows OpenSSH uses administrators_authorized_keys for admin accounts and
REM %USERPROFILE%\.ssh\authorized_keys for standard accounts. Cover both.
powershell -NoProfile -Command ^
  "$k='%PUBKEY%';" ^
  "$admins=Join-Path $env:ProgramData 'ssh\administrators_authorized_keys';" ^
  "$user=Join-Path $env:USERPROFILE '.ssh\authorized_keys';" ^
  "foreach($f in @($admins,$user)){ New-Item -ItemType Directory -Force -Path (Split-Path $f) | Out-Null; if(-not(Test-Path $f) -or -not(Select-String -Path $f -SimpleMatch $k -Quiet)){ Add-Content -Path $f -Value $k } };" ^
  "icacls $admins /inheritance:r /grant 'SYSTEM:F' /grant 'Administrators:F' | Out-Null"

echo [5/5] Done.
echo.
echo   Put these in hosts.conf on the openclaw VM:
REM Do the whole thing inside PowerShell so there is no batch-level pipe to escape.
powershell -NoProfile -Command "$ip=(& \"$env:ProgramFiles\Tailscale\tailscale.exe\" ip -4 | Select-Object -First 1); Write-Host ('    windows      ' + $ip + '   ' + $env:USERNAME + '   22')"
echo.
echo   Tip: keep this PC awake while using grok (Settings ^> Power ^> never sleep),
echo        it must stay on to relay the connection.
echo.
pause
