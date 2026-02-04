#!/bin/bash
set -e

VECTORSCAN_VERSION="${VECTORSCAN_VERSION:-5.4.12}"
BUILD_DIR="build/vectorscan"

echo "Building Vectorscan ${VECTORSCAN_VERSION} static libraries..."

# Determine platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Normalize architecture names
case "$ARCH" in
    x86_64)
        ARCH="amd64"
        ;;
    aarch64)
        ARCH="arm64"
        ;;
esac

PLATFORM_DIR="$BUILD_DIR/${OS}_${ARCH}"
mkdir -p "$PLATFORM_DIR/lib"
mkdir -p "$PLATFORM_DIR/include"

echo "Platform: ${OS}_${ARCH}"

# Check if Vectorscan is already built
if [ -f "$PLATFORM_DIR/lib/libhs.a" ]; then
    echo "Vectorscan static library already exists at $PLATFORM_DIR/lib/libhs.a"
    exit 0
fi

# Install build dependencies based on OS
install_dependencies() {
    if [ "$OS" = "linux" ]; then
        echo "Installing build dependencies (requires sudo)..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y \
                build-essential \
                cmake \
                ragel \
                pkg-config \
                libboost-dev \
                libsqlite3-dev \
                libpcap-dev
        elif command -v yum &> /dev/null; then
            sudo yum install -y \
                gcc gcc-c++ make \
                cmake \
                ragel \
                sqlite-devel \
                libpcap-devel \
                pkgconfig
        else
            echo "Warning: Unknown package manager. Please install cmake, ragel, sqlite, libpcap manually."
        fi
    elif [ "$OS" = "darwin" ]; then
        echo "Installing build dependencies via Homebrew..."
        if ! command -v brew &> /dev/null; then
            echo "Error: Homebrew not found. Please install Homebrew first."
            exit 1
        fi
        brew install cmake ragel boost pkg-config sqlite libpcap
    fi
}

# Build Vectorscan from source
build_vectorscan() {
    # Save the original directory before cd'ing
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

    echo "Building static library..."
    mkdir build
    cd build

    # Configure with static library build
    # Disable FAT_RUNTIME on macOS as it requires GNU binutils (objcopy) which doesn't exist on macOS
    CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON -DBUILD_EXAMPLES=OFF -DBUILD_TOOLS=OFF -DCMAKE_INSTALL_PREFIX=$INSTALL_PREFIX"
    if [ "$OS" = "darwin" ]; then
        CMAKE_FLAGS="$CMAKE_FLAGS -DFAT_RUNTIME=OFF"
    fi

    cmake .. $CMAKE_FLAGS

    # Build
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

    # Install to our platform directory
    make install

    echo "Vectorscan built successfully!"
    ls -lh "$INSTALL_PREFIX/lib/"
}

# Main execution
install_dependencies
build_vectorscan

echo "Vectorscan static library ready at: $PLATFORM_DIR/lib/libhs.a"
