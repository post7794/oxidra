[CmdletBinding()]
param(
    [string]$Version = "latest",
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "Programs\Oxidra\bin"),
    [string]$Repository = "post7794/oxidra",
    [switch]$AddToPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not [Environment]::Is64BitOperatingSystem) {
    throw "Oxidra currently publishes only a 64-bit Windows binary."
}

$asset = "oxidra-x86_64-pc-windows-msvc.zip"
$releaseBase = "https://github.com/$Repository/releases"
if ($Version -eq "latest") {
    $downloadBase = "$releaseBase/latest/download"
} else {
    $tag = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
    $downloadBase = "$releaseBase/download/$tag"
}

$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("oxidra-install-" + [guid]::NewGuid().ToString("N"))
$archive = Join-Path $tempDir $asset
$checksumFile = "$archive.sha256"

try {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    Write-Host "Downloading Oxidra ($Version)..."
    Invoke-WebRequest -UseBasicParsing -Uri "$downloadBase/$asset" -OutFile $archive
    Invoke-WebRequest -UseBasicParsing -Uri "$downloadBase/$asset.sha256" -OutFile $checksumFile

    $expected = ((Get-Content -LiteralPath $checksumFile -Raw).Trim() -split '\s+')[0]
    if ($expected -notmatch '^[0-9a-fA-F]{64}$') {
        throw "Release checksum file is malformed."
    }
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    if (-not $actual.Equals($expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw "SHA256 verification failed. Expected $expected, got $actual."
    }
    Write-Host "SHA256 verified."

    $expanded = Join-Path $tempDir "expanded"
    Expand-Archive -LiteralPath $archive -DestinationPath $expanded
    $executable = Join-Path $expanded "oxidra.exe"
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "The release archive does not contain oxidra.exe."
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item -LiteralPath $executable -Destination (Join-Path $InstallDir "oxidra.exe") -Force
} finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force
    }
}

$resolvedInstallDir = (Resolve-Path -LiteralPath $InstallDir).Path
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathEntries = @($userPath -split ';' | Where-Object { $_ })
$alreadyOnPath = $pathEntries | Where-Object {
    $_.TrimEnd('\') -ieq $resolvedInstallDir.TrimEnd('\')
}

if ($AddToPath -and -not $alreadyOnPath) {
    $newPath = if ([string]::IsNullOrWhiteSpace($userPath)) {
        $resolvedInstallDir
    } else {
        "$($userPath.TrimEnd(';'));$resolvedInstallDir"
    }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    $env:Path = "$resolvedInstallDir;$env:Path"
    Write-Host "Added $resolvedInstallDir to the user PATH."
} elseif (-not $alreadyOnPath) {
    Write-Host ""
    Write-Host "Oxidra was installed, but its directory is not on PATH."
    Write-Host "Re-run with -AddToPath, or add this directory to your user PATH:"
    Write-Host "  $resolvedInstallDir"
}

Write-Host ""
Write-Host "Installed: $resolvedInstallDir\oxidra.exe"
Write-Host "Open a new terminal, then run: oxidra --version"
