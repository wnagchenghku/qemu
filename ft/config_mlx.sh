#!/usr/bin/env bash

dest_host=192.168.100.1
#dest_host=fe80::94c9:3aff:fe50:83fc%br2  # for g8 ipv6
src=192.168.100.1
target=192.168.100.1
dest=192.168.123.2 # ip address to login to guest

iscsi=0
#iscsi=1

iscsiboot=0

if [ $iscsi -eq 0 ] ; then
    iscsiboot=1
    #iscsiboot=0
fi

destfile=/kvm_repo/vmbase_local

network=1 # use networking at all (for nested)
bridge_type="linux"
switch=virbr1
