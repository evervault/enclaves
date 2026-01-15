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
  cd runit-2.2.0
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


IP6TABLES_PATH=`command -v ip6tables`
if [ -z "$IP6TABLES_PATH" ]; then
  IP6TABLES_TARGET_PATH=/usr/local/bin/ip6tables
  echo "Installing prebuilt ip6tables"
  install -m 0755 ./iptables-1.8.10/iptables/xtables-legacy-multi "$IP6TABLES_TARGET_PATH" 
  IP6TABLES_PATH_POST_INSTALL=`command -v ip6tables`
  echo "IP6TABLES_PATH_POST_INSTALL: $IP6TABLES_PATH_POST_INSTALL"
  test "$IP6TABLES_PATH_POST_INSTALL" = "$IP6TABLES_TARGET_PATH" || exit 1
  echo "ip6tables installed successfully"
fi


IP_PATH=`command -v ip`
if [ -z "$IP_PATH" ]; then
  echo "Installing prebuilt ip"
  IP_TARGET_PATH=/usr/local/bin/ip 
  install -m 0755 ./iproute2-6.11.0/ip "$IP_TARGET_PATH"
  IP_PATH_POST_INSTALL=`command -v ip`
  echo "IP_PATH_POST_INSTALL: $IP_PATH_POST_INSTALL"
  test "$IP_PATH_POST_INSTALL" = "$IP_TARGET_PATH" || exit 1
  echo "ip installed successfully"
fi

exit 0