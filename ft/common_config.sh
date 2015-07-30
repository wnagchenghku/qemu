#!/usr/bin/env bash

# Better way of getting absolute path instead of relative path
if [ $0 != "-bash" ] ; then
        pushd `dirname "$0"` 2>&1 > /dev/null
fi
dir=$(pwd)
if [ $0 != "-bash" ] ; then
        popd 2>&1 > /dev/null
fi

arch=$(uname -m)
if [ $arch == 'ppc64le' ] ; then
    arch='ppc64'
fi

#source ${dir}/config_ib.sh
#source ${dir}/config_roce.sh
#source ${dir}/config_sde.sh
#source ${dir}/config_nested.sh
#source ${dir}/config_iwarp.sh
#source ${dir}/config_local.sh
source ${dir}/config_mlx.sh

bootwait=40 # time to wait for guest to bootup
#bootwait=180 # time to wait for guest to bootup
appwait=10 # time to wait for application to run
killwait=60 # time to wait for MC recovery

if [ "$arch" == "ppc64" ] ; then
    terminal=hvc0
else
    terminal=ttyS0
fi

#mc_net_disable=on
mc_net_disable=off

mc_disk_disable=on
#mc_disk_disable=off

mc_ppc_cheat_tce=on
#mc_ppc_cheat_tce=off

username=root
evalwait=20

autoconverge=on
#autoconverge=off

#gdb=0  # attach GDB to QEMU?
gdb=1

use_cmdline=0
#use_cmdline=1

#mc=1
mc=0

#mc_rdma_copy=on
mc_rdma_copy=off

#pin_all=off
pin_all=on

if [ ${use_cmdline} -eq 0 ] ; then
    proto=rdma
#    proto=tcp
#    proto=x-rdma
    display=50
    host=$dest_host
fi

#downtime=0.1  # requested downtime in seconds of the migration
#downtime=0.2
#downtime=0.3
#downtime=0.36
#downtime=0.4
#downtime=0.5
#downtime=0.6
#downtime=0.8
#downtime=1.0
#downtime=2.0
downtime=4.0
#downtime=8.0
#downtime=20.0

#migrate_loop=1
migrate_loop=0

qemu_loop=0
#qemu_loop=1

mcdelay=100

#rdma_keepalive=off
rdma_keepalive=on

ext=qcow2   # format of guest image filesystem
#mem=12000  # how much guest RAM?
#mem=13000
#mem=8192
#mem=4096
mem=2048
#mem=2047
#mem=1024
((mlgmem=mem*6/10))
#((mlgmem=mem*1/10))
#mlgmem=0
mlgwrite=75
#mlgwrite=5

disk=cloudbench_tinyvm
#disk=cloudbench_tinyvm_ppc64le
#disk=cloudbench_tinyvm_ppc64le2
#disk=cloudbench_nested_32bit

#user=" -runas mrhines"
user=""

backup_breakpoint1="b ram_save_complete"
backup_breakpoint1=""
backup_breakpoint2="b capture_checkpoint"
backup_breakpoint2=""
backup_breakpoint3="b qemu_rdma_post_send_remote_info"
backup_breakpoint3=""
backup_breakpoint4="b mc_recv"
backup_breakpoint4=""

primary_breakpoint1="b ram_save_complete" 
primary_breakpoint1=""
primary_breakpoint2="b spapr_reset_htab"
primary_breakpoint2=""
primary_breakpoint3="b htab_save_setup"
primary_breakpoint3=""
primary_breakpoint4="b migrate_init"
primary_breakpoint4=""

#trace="-trace events=$dir/ftevents"
trace=""

function blowawaypids {
        extraexclude="$2"
        pids="$(pgrep -f "$1")"
        tmp_pids="$(pgrep -f "(alltray|gnome-terminal|konsole|vim|ssh${extraexclude})")"
        if [ x"$tmp_pids" != x ] ; then
                for tmp in $tmp_pids ; do
                        #echo "throwing out $(ps -ef | grep $tmp | grep -v grep)"
                        pids=$(echo $pids | sed "s/$tmp//g")
                done
        fi
        for pid in $pids ; do
                if [ $pid != $$ ] && [ $pid != $PPID ] ; then
                        #echo "killing pid $pid"
                        kill -9 $pid > /dev/null 2>&1
                fi
        done
}                          

function sshawaypids {
    ssh -t -t root@$2 "cd $dir; source common_config.sh; blowawaypids $1"
}
