# SecLens-MCP Universal Windows Installer (PowerShell)
# Repository: https://github.com/thetuxify/seclens-mcp

$ErrorActionPreference = "Stop"

$Repo = "thetuxify/seclens-mcp"
$BinName = "seclens-mcp.exe"
$InstallDir = "$env:LOCALAPPDATA\Programs\SecLens"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         SecLens-MCP Windows Universal Installer          " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Detect Architecture
$Arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
if ($Arch -ne "X64") {
    Write-Warning "Detected Architecture: $Arch. Currently x64 binary is provided."
}

$ZipName = "seclens-mcp-windows-x86_64.zip"
$DownloadUrl = "https://github.com/$Repo/releases/latest/download/$ZipName"
$TempZip = Join-Path $env:TEMP $ZipName

Write-Host "[*] Creating target directory: $InstallDir" -ForegroundColor Gray
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

Write-Host "[*] Downloading SecLens-MCP from: $DownloadUrl" -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing
    Write-Host "[*] Extracting package..." -ForegroundColor Gray
    Expand-Archive -Path $TempZip -DestinationPath $InstallDir -Force
    Remove-Item -Path $TempZip -Force
} catch {
    Write-Warning "Could not download remote release. Looking for local build..."
    $LocalBin = ".\src\target\release\$BinName"
    if (Test-Path $LocalBin) {
        Copy-Item -Path $LocalBin -Destination "$InstallDir\$BinName" -Force
        Write-Host "[+] Copied from local release build: $LocalBin" -ForegroundColor Green
    } else {
        $LocalDebug = ".\src\target\debug\$BinName"
        if (Test-Path $LocalDebug) {
            Copy-Item -Path $LocalDebug -Destination "$InstallDir\$BinName" -Force
            Write-Host "[+] Copied from local debug build: $LocalDebug" -ForegroundColor Green
        } else {
            Write-Error "Failed to install SecLens-MCP: Release download failed and local build not found."
            exit 1
        }
    }
}

# 2. Add to User Path if missing
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "[*] Adding $InstallDir to User PATH..." -ForegroundColor Cyan
    [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
    $env:Path += ";$InstallDir"
}

Write-Host "`n[✓] SecLens-MCP installed successfully!" -ForegroundColor Green
Write-Host "[*] Binary path: $InstallDir\$BinName" -ForegroundColor Yellow
Write-Host "`nYou can now configure SecLens in Claude Desktop, Cursor or Antigravity." -ForegroundColor White
