# Build script for Intel Hyperscan on Windows
# Requires: Visual Studio 2017+ with C++ tools, CMake, Git
param(
    [string]$HyperscanVersion = "5.4.2"
)

$ErrorActionPreference = "Stop"

Write-Host "Building Intel Hyperscan ${HyperscanVersion} static libraries for Windows..." -ForegroundColor Green

# Determine architecture
$Arch = $env:PROCESSOR_ARCHITECTURE
if ($Arch -eq "AMD64") {
    $Arch = "amd64"
} elseif ($Arch -eq "ARM64") {
    $Arch = "arm64"
}

$BuildDir = "build\hyperscan"
$PlatformDir = "$BuildDir\windows_${Arch}"
$LibDir = "$PlatformDir\lib"
$IncludeDir = "$PlatformDir\include"

# Create directories
New-Item -ItemType Directory -Force -Path $LibDir | Out-Null
New-Item -ItemType Directory -Force -Path $IncludeDir | Out-Null

Write-Host "Platform: windows_${Arch}" -ForegroundColor Cyan

# Check if Hyperscan is already built
$StaticLib = "$LibDir\hs.lib"
if (Test-Path $StaticLib) {
    Write-Host "Hyperscan static library already exists at $StaticLib" -ForegroundColor Yellow
    exit 0
}

# Check for required tools
Write-Host "Checking for required build tools..." -ForegroundColor Cyan

# Check for CMake
if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
    Write-Host "Error: CMake not found. Please install CMake and add it to PATH." -ForegroundColor Red
    Write-Host "Download from: https://cmake.org/download/" -ForegroundColor Yellow
    exit 1
}

# Check for Visual Studio
$VSWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $VSWhere)) {
    Write-Host "Error: Visual Studio not found. Please install Visual Studio 2017 or later with C++ tools." -ForegroundColor Red
    exit 1
}

$VSPath = & $VSWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $VSPath) {
    Write-Host "Error: Visual Studio C++ tools not found. Please install C++ build tools." -ForegroundColor Red
    exit 1
}

Write-Host "Found Visual Studio at: $VSPath" -ForegroundColor Green

# Install vcpkg dependencies if vcpkg is available
if (Get-Command vcpkg -ErrorAction SilentlyContinue) {
    Write-Host "Installing dependencies via vcpkg..." -ForegroundColor Cyan
    vcpkg install boost-system boost-filesystem boost-thread ragel pcre --triplet=x64-windows-static
} else {
    Write-Host "Warning: vcpkg not found. Assuming dependencies are already installed." -ForegroundColor Yellow
    Write-Host "If build fails, install vcpkg and run: vcpkg install boost-system boost-filesystem boost-thread ragel pcre --triplet=x64-windows-static" -ForegroundColor Yellow
}

# Build Hyperscan from source
Write-Host "Building Intel Hyperscan from source..." -ForegroundColor Cyan

$WorkDir = New-TemporaryFile | ForEach-Object { Remove-Item $_; New-Item -ItemType Directory -Path $_ }
$OriginalDir = Get-Location
$InstallPrefix = Join-Path $OriginalDir $PlatformDir

try {
    Set-Location $WorkDir

    # Download Hyperscan
    Write-Host "Downloading Intel Hyperscan ${HyperscanVersion}..." -ForegroundColor Cyan
    $DownloadUrl = "https://github.com/intel/hyperscan/archive/refs/tags/v${HyperscanVersion}.tar.gz"
    $TarFile = "hyperscan.tar.gz"

    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TarFile -UseBasicParsing

    # Extract (requires tar which is available in Windows 10+)
    Write-Host "Extracting..." -ForegroundColor Cyan
    tar -xzf $TarFile

    $ExtractedDir = Get-ChildItem -Directory | Select-Object -First 1
    Set-Location $ExtractedDir.FullName

    # Create build directory
    New-Item -ItemType Directory -Force -Path "build" | Out-Null
    Set-Location "build"

    Write-Host "Configuring with CMake..." -ForegroundColor Cyan

    # Determine vcpkg toolchain file
    $VcpkgToolchain = $null
    if ($env:VCPKG_ROOT) {
        $VcpkgToolchain = "$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake"
        Write-Host "Using vcpkg toolchain from VCPKG_ROOT: $VcpkgToolchain" -ForegroundColor Green
    } elseif (Get-Command vcpkg -ErrorAction SilentlyContinue) {
        $VcpkgPath = (Get-Command vcpkg).Source
        $VcpkgRoot = Split-Path (Split-Path $VcpkgPath)
        $VcpkgToolchain = "$VcpkgRoot\scripts\buildsystems\vcpkg.cmake"
        Write-Host "Using vcpkg toolchain from vcpkg command: $VcpkgToolchain" -ForegroundColor Green
    }

    # Configure CMake for static library build
    # Use Visual Studio generator
    $CMakeArgs = @(
        "..",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DBUILD_SHARED_LIBS=OFF",
        "-DBUILD_STATIC_LIBS=ON",
        "-DBUILD_EXAMPLES=OFF",
        "-DBUILD_TOOLS=OFF",
        "-DCMAKE_INSTALL_PREFIX=$InstallPrefix",
        "-G", "Visual Studio 17 2022",
        "-A", "x64",
        "-DVCPKG_TARGET_TRIPLET=x64-windows-static"
    )

    # Add vcpkg toolchain file if found
    if ($VcpkgToolchain -and (Test-Path $VcpkgToolchain)) {
        $CMakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$VcpkgToolchain"
        Write-Host "✓ vcpkg toolchain file found and will be used" -ForegroundColor Green
    } else {
        Write-Host "Warning: vcpkg toolchain file not found. Dependencies may not be located." -ForegroundColor Yellow
    }

    & cmake @CMakeArgs

    if ($LASTEXITCODE -ne 0) {
        throw "CMake configuration failed"
    }

    Write-Host "Building Hyperscan..." -ForegroundColor Cyan
    cmake --build . --config Release --parallel

    if ($LASTEXITCODE -ne 0) {
        throw "Build failed"
    }

    Write-Host "Installing to $InstallPrefix..." -ForegroundColor Cyan
    cmake --install . --config Release

    if ($LASTEXITCODE -ne 0) {
        throw "Installation failed"
    }

    Write-Host "Hyperscan built successfully!" -ForegroundColor Green
    Get-ChildItem -Path "$InstallPrefix\lib" -File | ForEach-Object {
        Write-Host "  $($_.Name) - $([math]::Round($_.Length / 1MB, 2)) MB" -ForegroundColor Gray
    }

} catch {
    Write-Host "Error during build: $_" -ForegroundColor Red
    exit 1
} finally {
    Set-Location $OriginalDir
    Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue
}

Write-Host "`nHyperscan static library ready at: $StaticLib" -ForegroundColor Green
