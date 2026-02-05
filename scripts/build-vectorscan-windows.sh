#!/bin/bash
# Build script for Vectorscan on Windows x86_64 using MinGW-w64
# Uses official VectorCamp/vectorscan with MinGW support (PR #121)

set -e

VECTORSCAN_VERSION="${VECTORSCAN_VERSION:-5.4.12}"
BUILD_DIR="build/vectorscan"
PLATFORM_DIR="$BUILD_DIR/windows_amd64"

echo "Building Vectorscan ${VECTORSCAN_VERSION} for Windows x86_64 with MinGW..."

# Check if we're running in MSYS2 environment
if [[ -z "$MSYSTEM" ]]; then
    echo "Warning: Not running in MSYS2 environment"
    echo "This script should be run in MSYS2 MINGW64 shell"
fi

# Create platform directories
mkdir -p "$PLATFORM_DIR/lib"
mkdir -p "$PLATFORM_DIR/include"

echo "Platform: windows_amd64"

# Check if Vectorscan is already built
if [ -f "$PLATFORM_DIR/lib/libhs.a" ]; then
    echo "Vectorscan static library already exists at $PLATFORM_DIR/lib/libhs.a"
    exit 0
fi

# Install dependencies via pacman if needed
install_dependencies() {
    echo "Checking for required dependencies..."

    # List of required packages for MINGW64
    REQUIRED_PKGS=(
        "mingw-w64-x86_64-gcc"
        "mingw-w64-x86_64-cmake"
        "mingw-w64-x86_64-boost"
        "mingw-w64-x86_64-ragel"
        "mingw-w64-x86_64-pcre"
        "mingw-w64-x86_64-sqlite3"
        "mingw-w64-x86_64-pkg-config"
    )

    MISSING_PKGS=()
    for pkg in "${REQUIRED_PKGS[@]}"; do
        if ! pacman -Q "$pkg" &>/dev/null; then
            MISSING_PKGS+=("$pkg")
        fi
    done

    if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
        echo "Installing missing dependencies: ${MISSING_PKGS[*]}"
        pacman -S --noconfirm --needed "${MISSING_PKGS[@]}"
    else
        echo "All dependencies already installed"
    fi
}

# Build Vectorscan from source
build_vectorscan() {
    ORIGINAL_DIR="$(pwd)"
    INSTALL_PREFIX="$ORIGINAL_DIR/$PLATFORM_DIR"

    WORK_DIR=$(mktemp -d)
    trap "rm -rf $WORK_DIR" EXIT

    cd "$WORK_DIR"

    echo "Downloading Vectorscan ${VECTORSCAN_VERSION}..."
    curl -L --fail --silent --show-error \
        "https://github.com/VectorCamp/vectorscan/archive/refs/tags/vectorscan/${VECTORSCAN_VERSION}.tar.gz" \
        -o vectorscan.tar.gz

    echo "Extracting..."
    tar xzf vectorscan.tar.gz
    cd "vectorscan-vectorscan-${VECTORSCAN_VERSION}"

    echo "Applying Windows compatibility patches..."
    # Fix type mismatch in fdr_engine_description.cpp for Windows (size_t is unsigned long long on Win64)
    sed -i 's/std::min(min_len - 1, 2UL)/std::min(min_len - 1, 2ULL)/g' src/fdr/fdr_engine_description.cpp

    echo "Building static library with MinGW..."
    mkdir build
    cd build

    # Configure with CMake using MSYS Makefiles (for MSYS2 environment)
    cmake .. \
        -G "MSYS Makefiles" \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_STATIC_LIBS=ON \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_TOOLS=OFF \
        -DCMAKE_INSTALL_PREFIX="$INSTALL_PREFIX" \
        -DFAT_RUNTIME=OFF \
        -DBUILD_AVX2=ON \
        -DBUILD_AVX512=OFF \
        -DCMAKE_C_FLAGS="-D_WIN32_WINNT=0x0601" \
        -DCMAKE_CXX_FLAGS="-D_WIN32_WINNT=0x0601"

    # Build
    NPROC=$(nproc 2>/dev/null || echo 4)
    echo "Building with $NPROC parallel jobs..."
    make -j$NPROC

    # Install to our platform directory
    make install

    echo "Vectorscan built successfully!"
    ls -lh "$INSTALL_PREFIX/lib/"
}

# Main execution
install_dependencies
build_vectorscan

echo ""
echo "Vectorscan static library ready at: $PLATFORM_DIR/lib/libhs.a"
echo ""
echo "Output files:"
echo "  Static library: $(pwd)/$PLATFORM_DIR/lib/libhs.a"
echo "  Headers: $(pwd)/$PLATFORM_DIR/include/"
