#!/bin/sh

set -e

# Rudimentary test script to ensure all binaries are available on multiple distros

# Cannot use runit directly
command -v runit

command -v ifconfig
# Run base command (list interfaces)
ifconfig

command -v iptables
iptables -h

command -v ip
# List available addresses
ip addr