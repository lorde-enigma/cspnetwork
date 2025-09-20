#!/bin/bash

set -e

echo "building seeded vpn server..."

if [ ! -d "build" ]; then
    mkdir build
fi

cd build

cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

echo "build complete: build/cspnetwork"

if [ "$1" = "install" ]; then
    echo "installing system service..."
    cd ..
    sudo bash scripts/install.sh
fi
