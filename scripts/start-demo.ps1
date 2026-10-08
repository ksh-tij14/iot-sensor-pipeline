<#
Starts the whole pipeline and checks the sensor board is pointed at this PC.

Usage (from the repo root, in PowerShell):
    powershell -ExecutionPolicy Bypass -File scripts\start-demo.ps1
    powershell -ExecutionPolicy Bypass -File scripts\start-demo.ps1 -FixFirmware

-FixFirmware: if the PC's IP changed, update GATEWAY_URL in the firmware and
re-flash the board (it must be plugged in by USB).
-Virtual: also start the virtual sensor board (esp32-002), so the dashboard has
live readings even without the physical board.
#>
param([switch]$FixFirmware, [switch]$Virtual)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$Root = Split-Path -Parent $PSScriptRoot
$Pio = Join-Path $env:USERPROFILE ".platformio\penv\Scripts\pio.exe"
$MainCpp = Join-Path $Root "firmware\src\main.cpp"

function Step($text) { Write-Host "`n== $text" -ForegroundColor Cyan }

# 1. Docker Desktop must be running.
Step "Checking Docker"
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    $exe = @("$env:LOCALAPPDATA\Programs\DockerDesktop\Docker Desktop.exe",
             "C:\Program Files\Docker\Docker\Docker Desktop.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $exe) { throw "Docker Desktop not found. Install it from https://www.docker.com/products/docker-desktop/" }
    Write-Host "Starting Docker Desktop..."
    Start-Process $exe
    $deadline = (Get-Date).AddMinutes(3)
    do { Start-Sleep -Seconds 3; docker info *> $null } until ($LASTEXITCODE -eq 0 -or (Get-Date) -gt $deadline)
    if ($LASTEXITCODE -ne 0) { throw "Docker didn't start within 3 minutes. Open Docker Desktop manually and re-run." }
}
Write-Host "Docker is running."

# 2. Start the stack.
Step "Starting the pipeline (first run builds images, ~2 minutes)"
Push-Location (Join-Path $Root "docker")
try {
    # Builds the images only if they don't exist yet. Not redirected: PowerShell 5.1 turns redirected stderr progress lines into errors.
    if ($Virtual) { docker compose --profile demo up -d --wait } else { docker compose up -d --wait }
    if ($LASTEXITCODE -ne 0) { throw "docker compose failed - see the messages above." }
    docker compose ps --format "table {{.Service}}`t{{.Status}}"
} finally { Pop-Location }

# 3. Is the firmware pointed at this PC?
Step "Checking the board's gateway address"
$ip = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Wi-Fi" -ErrorAction SilentlyContinue |
       Select-Object -First 1).IPAddress
$network = (Get-NetConnectionProfile | Select-Object -First 1).Name
$fwIp = ([regex]::Match((Get-Content $MainCpp -Raw), '#define GATEWAY_URL "https?://([0-9.]+):')).Groups[1].Value
Write-Host "This PC:   $ip  (network: $network)"
Write-Host "Firmware:  $fwIp"

if (-not $ip) {
    Write-Host "No Wi-Fi address found. Connect this PC to the same hotspot as the board." -ForegroundColor Yellow
} elseif ($ip -eq $fwIp) {
    Write-Host "Match - the board will reach this PC." -ForegroundColor Green
} elseif ($FixFirmware) {
    Write-Host "Updating firmware to $ip and re-flashing..."
    $src = (Get-Content $MainCpp -Raw).Replace("://$fwIp`:", "://$ip`:")
    [IO.File]::WriteAllText($MainCpp, $src, (New-Object Text.UTF8Encoding $false))   # UTF-8 without BOM
    Push-Location (Join-Path $Root "firmware")
    try { & $Pio run -t upload; if ($LASTEXITCODE -ne 0) { throw "Upload failed - is the board plugged in?" } }
    finally { Pop-Location }
    Write-Host "Board re-flashed with the new address." -ForegroundColor Green
} else {
    Write-Host "MISMATCH - the board would send to the wrong address." -ForegroundColor Yellow
    Write-Host "Plug the board in by USB and re-run with -FixFirmware."
}

Step "Ready"
Start-Process "http://localhost:8080"   # open the dashboard in the default browser
Write-Host @"
Dashboard:                  http://localhost:8080  (opened in your browser)
Watch raw logs:             cd docker; docker compose logs -f gateway-1 validation
Run the attack demo:        cd docker; docker compose run --rm attack-simulator
API docs in your browser:   http://localhost:8001/docs
Stop everything:            cd docker; docker compose down
"@
