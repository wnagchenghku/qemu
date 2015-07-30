#!/usr/bin/env bash

dest_host=g14
#dest_host=fe80::202:c903:8:e3e3%ib0 # for g14 ipv6
src=klinux13
target=klinux14
dest=172.16.100.31 # ip address to login to guest

iscsi=0
#iscsi=1

iscsiboot=0

if [ $iscsi -eq 0 ] ; then
    iscsiboot=1
    #iscsiboot=0
fi

destfile=/kvm_repo/vmbase_ib

network=1
bridge_type="linux"
switch=br0

