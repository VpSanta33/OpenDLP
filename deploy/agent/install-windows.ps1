# Windows 安装脚本（以管理员身份运行 PowerShell）
#   .\install-windows.ps1 -Server https://dlp.corp.example -Token <注册令牌>
# 以「计划任务」方式在开机时以 SYSTEM 身份运行 Agent，异常退出后自动重启。
param(
  [Parameter(Mandatory = $true)][string]$Server,
  [Parameter(Mandatory = $true)][string]$Token,
  [string]$Binary = ".\opendlp-agent-windows-amd64.exe"
)
$ErrorActionPreference = "Stop"
$dir = Join-Path $env:ProgramFiles "OpenDLP"
$data = Join-Path $env:ProgramData "OpenDLP"
New-Item -ItemType Directory -Force -Path $dir, $data | Out-Null
Copy-Item $Binary (Join-Path $dir "opendlp-agent.exe") -Force

# 配置文件仅允许 SYSTEM 与管理员读取
$cfg = @{ server = $Server; enrollToken = $Token; removable = $true; scanSeconds = 5 } | ConvertTo-Json
Set-Content -Path (Join-Path $data "agent.json") -Value $cfg -Encoding UTF8
icacls $data /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

$exe = Join-Path $dir "opendlp-agent.exe"
$action = New-ScheduledTaskAction -Execute $exe -Argument "run -log-json"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "OpenDLP Agent" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName "OpenDLP Agent"
& $exe status
Write-Host "OpenDLP Agent 已安装并启动"
