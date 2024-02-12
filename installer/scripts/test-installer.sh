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

command -v ip6tables
ip6tables -h

command -v ev-ip
# Get version of iproute2
ev-ip -V