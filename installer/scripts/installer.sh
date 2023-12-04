#!/bin/sh

IFCONFIG_PATH=`command -v ifconfig`
if [ -z "$IFCONFIG_PATH" ]; then
  echo "Installing prebuilt ifconfig"
  IFCONFIG_TARGET_PATH=/usr/local/bin/ifconfig
  install -m 0755 net-tools-2.10/ifconfig "$IFCONFIG_TARGET_PATH"
  IFCONFIG_PATH_POST_INSTALL=`command -v ifconfig`
  test "$IFCONFIG_PATH_POST_INSTALL" = "$IFCONFIG_TARGET_PATH" || exit 1
  echo "ifconfig installed successfully"
fi

RUNIT_PATH=`command -v runit`
if [ -z "$RUNIT_PATH" ]; then
  echo "Installing prebuilt runit"
  cd runit-2.1.2
  sh ./package/upgrade
  RUNIT_PATH_POST_INSTALL=`command -v runit`
  if [ -z "$RUNIT_PATH_POST_INSTALL" ]; then
    exit 2
  fi
  cd ..
  echo "runit installed successfully"
fi

IPTABLES_PATH=`command -v iptables`
if [ -z "$IPTABLES_PATH" ]; then
  echo "Installing prebuilt iptables"
  IPTABLES_TARGET_PATH=/usr/local/bin/iptables
  mkdir -p /packages/iptables-1.8.10 
  install -m 0755 ./iptables-1.8.10/iptables/xtables-legacy-multi "$IPTABLES_TARGET_PATH"
  IPTABLES_PATH_POST_INSTALL=`command -v iptables`
  echo "IPTABLES_PATH_POST_INSTALL: $IPTABLES_PATH_POST_INSTALL"
  test "$IPTABLES_PATH_POST_INSTALL" = "$IPTABLES_TARGET_PATH" || exit 1
  echo "iptables installed successfully"
fi

exit 0