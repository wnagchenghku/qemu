#!/usr/bin/env bash
dir=$(echo $0 | sed -e "s/\(.*\/\)*.*/\1.\//g")

if [ x"$1" == x ] ; then
	echo "need DHCP server address"
	exit 1
fi

dhcp_server=$1
shift

if [ x"$1" == x ] ; then
	echo "need libvirt hypervisor hostname"
	exit 1
fi

libvirt_host=$1
shift

if [ x"$1" == x ] ; then
	echo "need libvirt guest VM name"
	exit 1
fi

name=$1
shift

#vprefix="virsh -c xen+tcp://$libvirt_host"
vprefix="virsh -c qemu+tcp://$libvirt_host/system"
mac=$($vprefix dumpxml $name | grep "mac address" | grep -oE "..:..:..:..:..:..")

if [ x"$mac" == x ] ; then
	echo "Could not get MAC from libvirt xml for VM $name"
	exit 1
fi

$dir/omapi_lookup_mac.py $dhcp_server $mac
exit $?
