#!/usr/bin/env bash

source $(echo $0 | sed -e "s/\(.*\/\)*.*/\1.\//g")/common.sh
source $(echo $0 | sed -e "s/\(.*\/\)*.*/\1.\//g")/common_config.sh

if [ $use_cmdline -eq 1 ] ; then
    if [ x"$1" == x ] ; then
            echo "need hostname/ip"
            exit 1
    fi
    host=$1
    shift

    if [ x"$1" == x ] ; then
            echo "need 'tcp' or 'mc' or 'rdma'"
            exit 1
    fi
    proto=$1
    shift
fi

blowawaypids backup.sh "|migrate_monitor"
blowawaypids rdmabackup "|migrate_monitor"

sshawaypids cu ${src}
sshawaypids rdmaprimary ${src}
sshawaypids primary.sh ${src}
sshawaypids rdmasource ${src}

serial="-serial tcp:0:5556,server,nowait"
nographic="-nographic -vnc 0:6"
replica_boot=""

if [ ${mc_disk_disable} == "off" ] ; then
    rm -f /kvm_repo/active_disk.qcow2
    rm -f /kvm_repo/hidden_disk.qcow2
    bytes=$( qemu-img info /kvm_repo/${disk}.${ext} | grep "virtual size" | grep -oE "[0-9]+ bytes" | cut -f 1 -d " ")
    qemu-img create -f qcow2 /kvm_repo/active_disk.qcow2 ${bytes}
    qemu-img create -f qcow2 /kvm_repo/hidden_disk.qcow2 ${bytes}

    if [ "$arch" != "ppc64" ] ; then
        replica_boot="-drive if=none,driver=${ext},file=${disk}.${ext},id=mc1,cache=none,aio=native -drive if=virtio,driver=replication,mode=secondary,throttling.bps-total-max=70000000,file.file.filename=/kvm_repo/active_disk.qcow2,file.driver=qcow2,file.backing.file.filename=/kvm_repo/hidden_disk.qcow2,file.backing.driver=qcow2,file.backing.allow-write-backing-file=on,file.backing.backing.backing_reference=mc1"
    else
        echo "ppc code not written yet. $arch"
        exit 1
    fi
else
    if [ $iscsi -eq 0 ] ; then
        rm -f $destfile 
        qemu-img create -b /kvm_repo/${disk}.${ext} -f ${ext} $destfile 
    fi
fi

rest=" -name rdmabackup -monitor unix:/tmp/devguest.dest,server,nowait -qmp tcp:0:4445,server,nowait $serial $nographic ${replica_boot}"

if [ $gdb -eq 1 ] ; then
    host=0
    #host="[::]"
    #host="[fe80::94c9:3aff:fe50:83fc%br2]"
    gdb $binary -ex "$backup_breakpoint1" -ex "$backup_breakpoint2" -ex "$backup_breakpoint3" -ex "$backup_breakpoint4" -ex "handle SIGUSR2 noprint" -ex "handle SIGPIPE noprint" -ex "run $run -incoming $proto:$host:3456 $rest" 
else
    echo "$binary ${run} -incoming $proto:$host:3456 $rest"
    $binary ${run} -incoming $proto:$host:3456 2>&1 $rest
fi
