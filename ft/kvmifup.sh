#!/bin/bash

source $(echo $0 | sed -e "s/\(.*\/\)*.*/\1.\//g")/common_config.sh

#export PATH=$PATH:/sbin:/usr/sbin:/usr/local/sbin
#sudo setcap cap_net_admin+ep /sbin/tunctl

function verify {
    if [ $1 -gt 0 ] ; then
        echo "Operation $2 failed. Bailing."
        exit 1
    fi 
}

if [ -n "$1" ];then
        ip link set $1 up
        if [ $mc -eq 1 ] && [ "x$mc_net_disable" == "xoff" ]; then
            #if [ "x$proto" == "xmc" ] || [ "x$proto" == "xx-mc" ] ; then
                ifb=$(echo $1 | sed "s/tap/ifb/g")

                echo "destroying $proto $ifb rules for nic: $1"
                tc filter del dev $1 parent ffff: proto ip pref 10 u32 match u32 0 0 action mirred egress redirect dev $ifb 
                tc qdisc del dev $1 ingress
                ip link set down $ifb 
                nl-qdisc-delete --dev=$ifb --parent=root plug

                echo "setting up $proto $ifb rules for nic: $1"
                ip link set up $ifb 
                verify $? "ip link set up $ifb"
                tc qdisc add dev $1 ingress
                verify $? "tc qdisc add dev $1 ingress"
                tc filter add dev $1 parent ffff: proto ip pref 10 u32 match u32 0 0 action mirred egress redirect dev $ifb 
                verify $? "tc filter add dev $1 parent ffff: proto ip pref 10 u32 match u32 0 0 action mirred egress redirect dev $ifb"
            #fi
        else
            echo "this is the destination (or we're not checkpointing). skipping ifb"
        fi

        sleep 1s
        if [ $bridge_type == "ovs" ] ; then
            ovs-vsctl add-port $switch $1
        else
            brctl addif $switch $1
        fi
        exit 0
else
        echo "Error: no interface specified"
        exit 1
fi
