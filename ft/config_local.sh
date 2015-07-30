#!/usr/bin/env bash

dest_host=127.0.0.1
#dest_host=fe80::202:c903:8:e3e3%ib0 # for g14 ipv6
src=127.0.0.1
target=127.0.0.1
dest=192.168.123.2 # ip address to login to guest

iscsi=0
#iscsi=1

iscsiboot=0

if [ $iscsi -eq 0 ] ; then
    iscsiboot=1
    #iscsiboot=0
fi

destfile=/kvm_repo/vmbase_local

network=1
bridge_type="linux"
switch=virbr1


