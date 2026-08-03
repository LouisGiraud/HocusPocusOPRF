#!/bin/bash
set -e  # Exit on first error

# ---------- CONFIG ----------
BUILD_DIR="build"
BUILD_TYPE="Release"
TEST_NAME="OPRF"  
# ----------------------------

echo "==> Cleaning old build..."
rm -rf "$BUILD_DIR"

echo "==> Creating build directory..."
mkdir "$BUILD_DIR"
cd "$BUILD_DIR"

echo "==> Running CMake..."
cmake -DCMAKE_BUILD_TYPE="$BUILD_TYPE" ..

echo "==> Building (verbose)..."
cmake --build . --verbose

if [ -n "$TEST_NAME" ]; then
    echo "==> Running test '$TEST_NAME'..."
    ctest -R "$TEST_NAME" -VV
fi

echo "==> All done!"