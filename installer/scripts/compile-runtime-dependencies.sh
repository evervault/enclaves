#!/bin/sh

cd packages

### Build runit
gunzip runit-2.1.2.tar.gz
tar -xpf runit-2.1.2.tar
cd admin/runit-2.1.2 # runit contains a top level folder called admin

# compile runit
echo "****************************"
echo "* compiling runit binaries *"
echo "****************************"
./package/compile
./package/check

# Create expected directories for runit
mkdir -p /output/runit-2.1.2/src

# Move compiled runit commands into output commands folder
echo "************************************"
echo "* copying runit binaries to output *"
echo "************************************"
cp -r command /output/runit-2.1.2

# Move compiled runit scripts into output scripts folder
cp -r ./package /output/runit-2.1.2

# navigate back to packages base
cd -
cd -

# extract net-tools source
cd /packages
echo "************************"
echo "* extracting net-tools *"
echo "************************"
unxz net-tools-2.10.tar.xz ; tar -xf net-tools-2.10.tar

echo "**********************"
echo "* building net-tools *"
echo "**********************"
cd net-tools-2.10
# Use preconfigured config for Cage environment
cp /packages/net-tools.h ./config.h


# Run make commands required for ifconfig, include static flag
CFLAGS="-O2 -g -static" make subdirs
CFLAGS="-O2 -g -static" make ifconfig

mkdir -p /output/net-tools-2.10

# Copy ifconfig binary to output directory
echo "*******************************"
echo "* copying ifconfig to outputs *"
echo "*******************************"
cp ./ifconfig /output/net-tools-2.10

# Create archive of static binaries and installer
echo "******************************"
echo "* creating installer archive *"
echo "******************************"
cp /packages/installer.sh /output/installer.sh
cd /output
tar -czf runtime-dependencies.tar.gz net-tools-2.10 runit-2.1.2 installer.sh

# Remove binaries outside of the archive
echo "*****************************"
echo "* removing unused artifacts *"
echo "*****************************"
rm -rf net-tools-2.10 runit-2.1.2 installer.sh
