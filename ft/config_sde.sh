#!/usr/bin/env bash

dest_host=192.168.200.25
#dest_host=fe80::94c9:3aff:fe50:83fc%br2  # for g8 ipv6
src=192.168.100.17
target=192.168.100.25
dest=192.168.100.1 # ip address to login to guest

iscsi=0
#iscsi=1

iscsiboot=0

if [ $iscsi -eq 0 ] ; then
    iscsiboot=1
    #iscsiboot=0
fi

destfile=/kvm_repo/vmbase_sde

network=0 # use networking at all (for nested)
bridge_type="ovs"
switch=br-int
