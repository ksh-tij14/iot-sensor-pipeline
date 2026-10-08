<#
Replaces the committed dev keys with real random ones, everywhere at once:
generates new keys, re-flashes the board so it stores its new key, and
restarts the Docker stack so the gateways, fork and dashboard use them.

The board must be plugged in by USB. From the repo root, in PowerShell:
    powershell -ExecutionPolicy Bypass -File scripts\rotate-keys.ps1
#>
$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false
$Root = Split-Path -Parent $PSScriptRoot
$Pio = Join-Path $env:USERPROFILE ".platformio\penv\Scripts\pio.exe"
$MainCpp = Join-Path $Root "firmware\src\main.cpp"

function Set-Reprovision($value) {
    $src = Get-Content $MainCpp -Raw
    $src = [regex]::Replace($src, '#define FORCE_REPROVISION \d', "#define FORCE_REPROVISION $value")
    [IO.File]::WriteAllText($MainCpp, $src, (New-Object Text.UTF8Encoding $false))   # UTF-8 without BOM
}
function Upload {
    Push-Location (Join-Path $Root "firmware")
    try { & $Pio run -t upload; if ($LASTEXITCODE -ne 0) { throw "Upload failed - is the board plugged in?" } }
    finally { Pop-Location }
}

# Check the board is connected BEFORE changing any keys, so a missing board
# can't leave the stack and the board holding different keys.
$ports = & $Pio device list 2>$null | Select-String -Pattern '^COM\d+'
if (-not $ports) { throw "No board found on USB. Plug the sensor board into this PC and re-run." }

Write-Host "`n== Generating new keys" -ForegroundColor Cyan
python (Join-Path $Root "scripts\generate_secrets.py")
if ($LASTEXITCODE -ne 0) { throw "Key generation failed." }

Write-Host "`n== Flashing the board so it stores its new key (2 uploads)" -ForegroundColor Cyan
Set-Reprovision 1
try {
    Upload                          # boots once, overwrites the stored key
    Start-Sleep -Seconds 8
} finally {
    Set-Reprovision 0               # never leave reprovisioning switched on
}
Upload                              # normal firmware again; the new key stays in flash

Write-Host "`n== Restarting the stack with the new keys" -ForegroundColor Cyan
Push-Location (Join-Path $Root "docker")
try {
    docker compose up -d --wait --build --force-recreate
    if ($LASTEXITCODE -ne 0) { throw "docker compose failed." }
} finally { Pop-Location }

Write-Host "`nDone. The dev keys in gateway/keystore.json no longer work against this stack." -ForegroundColor Green
