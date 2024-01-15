#!/bin/sh

# Rudimentary test script to ensure all binaries are available on multiple distros

command -v runit
runit --help

command -v ifconfig
ifconfig --help

command -v iptables
iptables --help

command -v ip
ip --help