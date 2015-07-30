#!/usr/bin/env bash
if [ x"$1" == x ] ; then
	echo "need DISPLAY port."
	exit 1
fi
display=$1
shift

#program=ftvm
program=qemu
ssh mrhines@172.16.1.222 -f "sleep 5; DISPLAY=:${display}.0 vncviewer klinux8:4"
ssh mrhines@172.16.1.222 -f "sleep 5; DISPLAY=:${display}.0 vncviewer klinux9:4"
chmod +x /home/mrhines/$program/x86_64-softmmu/qemu-system-x86_64
sleep 1
breakpoint1="b mc_thread"
breakpoint1=""
breakpoint2="b mc_put_buffer"
breakpoint2=""
breakpoint3="b migrate_fd_cleanup"
breakpoint3=""
breakpoint4="b migration.c:630"
breakpoint4=""

gdb /home/mrhines/$program/x86_64-softmmu/qemu-system-x86_64 -ex "$breakpoint1" -ex "$breakpoint2" -ex "$breakpoint3" -ex "$breakpoint4" -ex "handle SIGUSR2 noprint" -ex "handle SIGPIPE noprint" -ex "run -M pc-0.14 -enable-kvm -m 2048 -smp 2,sockets=1,cores=1,threads=1 -nodefconfig -rtc base=utc -no-shutdown /kvm_repo/cb/vmbase -serial pty -monitor unix:/tmp/devguest,server,nowait -netdev type=tap,vhost=on,id=hostnet0,script=/home/mrhines/ftvm/kvmifup.sh,downscript=/home/mrhines/ftvm/kvmifdown.sh -device virtio-net-pci,netdev=hostnet0,mac=12:34:36:00:00:02 -usb -device usb-tablet,id=input0 -vnc 0.0.0.0:4 -nographic -device virtio-balloon-pci,id=balloon0,bus=pci.0,addr=0x5" 2>&1
