#!/usr/bin/env bash

# This is how to setup a cgroup on the sender side:
#
# cd /sys/fs/cgroup/memory/libvirt/qemu
# echo "-1" > memory.memsw.limit_in_bytes
# echo "-1" > memory.limit_in_bytes
# echo $(pidof qemu-system-x86_64) > tasks
# echo 512M > memory.limit_in_bytes         # maximum RSS
# echo 3G > memory.memsw.limit_in_bytes     # maximum RSS + swap

# The above will ensure that migration does not use more than 512M
# but it does not know how to detect if a page is zero or not

dir=$(echo $0 | sed -e "s/\(.*\/\)*.*/\1.\//g")

if [ x"$1" == x ] ; then
	echo "need hostname/ip."
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

if [ x"$1" == x ] ; then
	echo "need DISPLAY port."
	exit 1
fi
display=$1
shift

source $(echo $0 | sed -e "s/\(.*\/\)*.*/\1.\//g")/common_config.sh

echo "Migrating: $host $proto $display..."

for num in $(seq $bootwait -1 1) ; do 
    echo "$num seconds until starting app..."
    sleep 1
done

echo "running mlg"

#ssh -t -t -i ${dir}/klab_id_rsa.${arch} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null username@${dest} -f "while true ; do date > /tmp/tmpdate; sudo write root ${terminal} < /tmp/tmpdate; sleep 1; done"
ssh -t -t -i ${dir}/klab_id_rsa.${arch} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $username@${dest} -f "ping google.com | while read line ; do echo \$line > /tmp/tmpping; sudo write root ${terminal} < /tmp/tmpping; done"

if [ $mlgmem -gt 0 ] ; then
    #ssh -t -t -i ${dir}/klab_id_rsa.${arch} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $username@${dest} -f "/home/$username/3rd_party/mlgsrc/mlg -t 1 -M $mlgmem -s 4 -a rand -r $mlgwrite -n 2000"
    ssh -t -t -i ${dir}/klab_id_rsa.${arch} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $username@${dest} -f "stress --vm-bytes ${mlgmem}M --vm 1 --vm-keep"
else
    echo "skipping mlg"
fi

sleep 2
reset
echo "letting workload run for $appwait seconds";

for num in $(seq $appwait -1 1); do 
    if [ $mlgmem -eq 0 ] ; then
        break
    fi
    echo "$num secs until next migration..."
    sleep 1
done

reset

#declare -a accum_caps
#curr_caps=0
#accum_caps[$curr_caps]

#ssh mrhines@172.16.1.222 -f "DISPLAY=:${display}.0 vncviewer ${target}:5"
#${dir}/qemu-monitor /tmp/devguest.source migrate_set_capability xbzrle on
#${dir}/qemu-monitor /tmp/devguest.source migrate_set_cache_size 256m
${dir}/qemu-monitor /tmp/devguest.source migrate-set-mc-delay $mcdelay
${dir}/qemu-monitor /tmp/devguest.source migrate_set_downtime $downtime
if [ "$mc" -eq 1 ] ; then
    ${dir}/qemu-monitor /tmp/devguest.source migrate_set_capability mc on
    ${dir}/qemu-monitor /tmp/devguest.source migrate_set_capability mc-net-disable $mc_net_disable
    ${dir}/qemu-monitor /tmp/devguest.source migrate_set_capability mc-disk-disable $mc_disk_disable
    ${dir}/qemu-monitor /tmp/devguest.source migrate_set_capability mc-ppc-cheat-tce $mc_ppc_cheat_tce

    if [ "$proto" == "rdma" ] || [ "$proto" == "x-rdma" ] ; then
        ${dir}/qemu-monitor /tmp/devguest.source migrate_set_capability mc-rdma-copy $mc_rdma_copy 
    fi
fi

if [ "$proto" == "rdma" ] || [ "$proto" == "x-rdma" ] ; then
    ${dir}/qemu-monitor /tmp/devguest.source migrate_set_capability ${proto}-pin-all $pin_all
    ${dir}/qemu-monitor /tmp/devguest.source migrate_set_capability rdma-keepalive $rdma_keepalive
fi

${dir}/qemu-monitor /tmp/devguest.source migrate_set_capability auto-converge $autoconverge
${dir}/qemu-monitor /tmp/devguest.source migrate_set_speed 40g

if [ x"$(echo $host | grep -E '\:')" == x ] ; then
    ${dir}/qemu-monitor /tmp/devguest.source migrate -d $proto:$host:3456
else
    ${dir}/qemu-monitor /tmp/devguest.source migrate -d $proto:[$host]:3456
fi

function do_flush {
    if [ x"$trace" != x ] ; then
        ${dir}/qemu-monitor /tmp/devguest.source trace-file flush
    fi
}

while true ; do 
    do_flush

	result="$(${dir}/qemu-monitor /tmp/devguest.source info migrate)"
	if [ x"$(echo "$result" | grep -iE "(completed|failed)")" != x ] ; then 
		break
	fi
	sleep 1.0s
	echo "$result"
	${dir}/qemu-monitor /tmp/devguest.source info migrate
    if [ $? -gt 0 ] ; then
        echo "monitor failure!"
        exit 1
    fi
done

do_flush

if [ $mc -eq 0 ] ; then
    echo "resuming"
    ssh $host "${dir}/qemu-monitor /tmp/devguest.dest c"
    echo "done"
fi

do_flush

${dir}/qemu-monitor /tmp/devguest.source info migrate
exit 0
