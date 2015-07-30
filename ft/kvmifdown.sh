#!/bin/bash

source $(echo $0 | sed -e "s/\(.*\/\)*.*/\1.\//g")/common_config.sh

#export PATH=$PATH:/sbin:/usr/sbin:/usr/local/sbin
#sudo setcap cap_net_admin+ep /sbin/tunctl

if [ -n "$1" ];then
        if [ $(ps -ef | grep migrate_monitor | grep -v grep | grep source | wc -l) -gt 0 ] ; then
            if [ $mc -eq 1 ] ; then
                ifb=$(echo $1 | sed "s/tap/ifb/g")
                echo "destroying $proto $ifb rules for nic: $1"
                tc filter del dev $1 parent ffff: proto ip pref 10 u32 match u32 0 0 action mirred egress redirect dev $ifb 
                tc qdisc del dev $1 ingress
                ip link set down $ifb 
                nl-qdisc-delete --dev=$ifb --parent=root plug
            fi
        else
            echo "this is the destination. skipping ifb"
        fi
        tunctl -d $1
        if [ $bridge_type == "ovs" ] ; then
            ovs-vsctl del-port $switch $1
        else
            brctl delif $switch $1
        fi
        ip link set $1 down 
        exit 0
else
        echo "Error: no interface specified"
        exit 1
fi
