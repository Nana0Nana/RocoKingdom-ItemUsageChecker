param(
    [string]$Python = "python",
    [string]$Name = "RocoKingdom-ItemUsageChecker",
    [switch]$OneFile
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Invoke-Step([string]$Message, [scriptblock]$Action) {
    Write-Host "[+] $Message"
    & $Action
    if ($LASTEXITCODE -ne 0) {
        throw "Step failed: $Message"
    }
}

Invoke-Step "Checking Python" {
    & $Python --version
}

Invoke-Step "Installing/Updating packaging tools" {
    & $Python -m pip install --disable-pip-version-check -U pip pyinstaller mitmproxy
}

$args = @(
    "-m", "PyInstaller",
    "--noconfirm",
    "--clean",
    "--name", $Name,
    "--distpath", (Join-Path $root "dist"),
    "--workpath", (Join-Path $root "build"),
    "--specpath", $root,
    "--collect-all", "mitmproxy",
    "--add-data", "viewer.html;.",
    "checkballs.py"
)

if ($OneFile) {
    $args += "--onefile"
}
else {
    $args += "--onedir"
}

Invoke-Step "Building executable" {
    & $Python @args
}

$output = if ($OneFile) {
    Join-Path $root "dist\$Name.exe"
} else {
    Join-Path $root "dist\$Name\$Name.exe"
}

Write-Host ""
Write-Host "[ok] Build finished: $output"
if (-not $OneFile) {
    Write-Host "[hint] Ship the whole dist\$Name folder, not only the exe."
}
