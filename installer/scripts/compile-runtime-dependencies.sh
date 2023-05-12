#!/bin/sh

set -e

# If running within github actions, operate within mounted FS, else operate from root
BASE_PATH=$GITHUB_WORKSPACE
OUTPUT_PATH="$BASE_PATH/output"

PACKAGES_PATH=/packages

# Cross-compiler for ARM
CROSS_COMPILE=aarch64-linux-gnu-gcc

### Build runit
gunzip runit-2.1.2.tar.gz
tar -xpf runit-2.1.2.tar

# Build runit for amd64
build_runit_amd64() {
    echo "****************************"
    echo "* Building runit for amd64 *"
    echo "****************************"

    cd ./admin/runit-2.1.2

    # Configure static compilation of runit using dietlibc for amd64
    echo 'gcc -O2 -Wall -static' > src/conf-cc
    echo 'gcc -static -Os -pipe' > src/conf-ld

    ./package/compile
    ./package/check

    # Create amd64 output directory
    mkdir -p "$OUTPUT_PATH/amd64/runit-2.1.2"
    cp -r command "$OUTPUT_PATH/amd64/runit-2.1.2"
    cp -r ./package "$OUTPUT_PATH/amd64/runit-2.1.2"

}

# Build runit for arm64
build_runit_arm64() {
    echo "****************************"
    echo "* Building runit for arm64 *"
    echo "****************************"

    cd ./admin/runit-2.1.2

    # Configure static compilation of runit using dietlibc for arm64
    echo "$CROSS_COMPILE -O2 -Wall -static" > src/conf-cc
    echo "$CROSS_COMPILE -static -Os -pipe" > src/conf-ld

    ./package/compile
    ./package/check

    # Create arm64 output directory
    mkdir -p "$OUTPUT_PATH/arm64/runit-2.1.2"
    cp -r command "$OUTPUT_PATH/arm64/runit-2.1.2"
    cp -r ./package "$OUTPUT_PATH/arm64/runit-2.1.2"
}

# Build runit for both architectures
build_runit_amd64
build_runit_arm64

# Build net-tools for amd64
build_net_tools_amd64() {
    echo "****************************"
    echo "* Building net-tools for amd64 *"
    echo "****************************"

    # Create amd64 output directory
    mkdir -p "$OUTPUT_PATH/amd64/net-tools-2.10"

    # Build net-tools for amd64
    echo "**********************"
    echo "* Building net-tools *"
    echo "**********************"
    (cd $PACKAGES_PATH/net-tools-2.10 &&
        cp "$PACKAGES_PATH/net-tools.h" ./config.h &&
        CFLAGS="-O2 -g -static" make subdirs &&
        CFLAGS="-O2 -g -static" make ifconfig)

    # Copy ifconfig binary to output directory
    echo "*******************************"
    echo "* Copying ifconfig to outputs *"
    echo "*******************************"
    mkdir -p "$OUTPUT_PATH/amd64/net-tools-2.10"
    cp $PACKAGES_PATH/net-tools-2.10/ifconfig "$OUTPUT_PATH/amd64/net-tools-2.10"
}

# Build net-tools for arm64
build_net_tools_arm64() {    
    echo "****************************"
    echo "* Building net-tools for arm64 *"
    echo "****************************"

    # Create arm64 output directory
    mkdir -p "$OUTPUT_PATH/arm64/net-tools-2.10"

    # Build net-tools for ARM
    echo "**********************"
    echo "* Building net-tools *"
    echo "**********************"
    (cd $PACKAGES_PATH/net-tools-2.10 &&
        cp "$PACKAGES_PATH/net-tools.h" ./config.h &&
        make CC=${CROSS_COMPILE} CFLAGS="-O2 -g -static" subdirs &&
        make CC=${CROSS_COMPILE} CFLAGS="-O2 -g -static" ifconfig &&
        cp ifconfig "$OUTPUT_PATH/arm64/net-tools-2.10")

    # Copy ifconfig binary to output directory
    echo "*******************************"
    echo "* Copying ifconfig to outputs *"
    echo "*******************************"
    mkdir -p "$OUTPUT_PATH/arm64/net-tools-2.10"
    cp $PACKAGES_PATH/net-tools-2.10/ifconfig "$OUTPUT_PATH/arm64/net-tools-2.10"
}

# extract net-tools source
cd $PACKAGES_PATH
echo "************************"
echo "* extracting net-tools *"
echo "************************"
xz -d net-tools-2.10.tar.xz ; tar -xf net-tools-2.10.tar

echo "**********************"
echo "* building net-tools *"
echo "**********************"
cd net-tools-2.10
# Use preconfigured config for Cage environment
cp "$PACKAGES_PATH/net-tools.h" ./config.h

build_net_tools_amd64
build_net_tools_arm64

# Create archive of static binaries and installer
echo "******************************"
echo "* creating installer archive *"
echo "******************************"
cp "$PACKAGES_PATH/installer.sh" "$OUTPUT_PATH/installer.sh"
cd $OUTPUT_PATH
tar -czf runtime-dependencies.tar.gz net-tools-2.10 runit-2.1.2 installer.sh

# Remove binaries outside of the archive
echo "*****************************"
echo "* removing unused artifacts *"
echo "*****************************"
rm -rf net-tools-2.10 runit-2.1.2 installer.sh
