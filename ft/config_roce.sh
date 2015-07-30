#!/usr/bin/env bash

dest_host=r8
#dest_host=fe80::94c9:3aff:fe50:83fc%br2  # for g8 ipv6
src=klinux9
target=klinux8
dest=172.16.7.165 # ip address to login to guest

#iscsi=0
iscsi=1

iscsiboot=0

if [ $iscsi -eq 0 ] ; then
    iscsiboot=1
    #iscsiboot=0
fi

destfile=/kvm_repo/vmbase_roce

network=1
bridge_type="linux"
switch=br0
