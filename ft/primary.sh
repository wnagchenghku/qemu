#!/usr/bin/env bash
source $(echo $0 | sed -e "s/\(.*\/\)*.*/\1.\//g")/common.sh
source $(echo $0 | sed -e "s/\(.*\/\)*.*/\1.\//g")/common_config.sh

if [ $use_cmdline -eq 1 ] ; then
    if [ x"$1" == x ] ; then
        echo "need DISPLAY port."
        exit 1
    fi
    display=$1
    shift
fi

#ssh root@172.16.1.222 "pkill -9 -f vncviewer"
#ssh mrhines@172.16.1.222 -f "sleep 5; DISPLAY=:${display}.0 vncviewer ${src}:5"

blowawaypids rdmaprimary

serial="-serial tcp:0:5555,server,nowait"
#nographic="-nographic"
nographic="-vnc 0:5"
replica_boot=""

if [ ${mc_disk_disable} == "off" ] ; then
    if [ "$arch" != "ppc64" ] ; then
        srcfile="/kvm_repo/${disk}.${ext}.srcreplica"
        replica_boot="-drive if=virtio,driver=quorum,read-pattern=fifo,no-connect=on,children.0.file.filename=${srcfile},children.0.driver=${ext},children.1.file.driver=nbd,children.1.file.export=mc1,children.1.file.host=${dest_host},children.1.file.port=6262,children.1.driver=replication,children.1.mode=primary,children.1.ignore-errors=on"
    else
        echo "ppc code not written yet."
        exit 1
    fi
fi
rest=" -name rdmaprimary -monitor unix:/tmp/devguest.source,server,nowait -qmp tcp:0:4444,server,nowait $serial $nographic ${replica_boot}"

if [ $gdb -eq 1 ] ; then
    gdb $binary -ex "$primary_breakpoint1" -ex "$primary_breakpoint2" -ex "$primary_breakpoint3" -ex "$primary_breakpoint4" -ex "handle SIGUSR2 noprint" -ex "handle SIGPIPE noprint" -ex "run $run $rest" 2>&1
else
    $binary ${run} $rest 2>&1
fi
