#!/usr/bin/env bash

source $(echo $0 | sed -e "s/\(.*\/\)*.*/\1.\//g")/common_config.sh

boot=""

binary=/home/mrhines/qemu/$arch-softmmu/qemu-system-$arch

if [ ${mc_net_disable} == "off" ] ; then
    if [ $iscsi -eq 0 ] ; then
        if [ "$arch" == "ppc64" ] ; then
            boot="-device virtio-blk-pci,scsi=off,bus=pci.0,drive=drive-virtio-disk0,id=virtio-disk0 -drive file=$destfile,if=none,id=drive-virtio-disk0"
            boot="-device spapr-vscsi,id=scsi0,reg=0x2000 ${boot}" 
            
        else
            boot="-drive file=$destfile,if=virtio"
        fi
    else
        if [ x"$iscsiboot" != x ] && [ $iscsiboot -eq 1 ] ; then
            echo "iscsi Boot is set. No disk will be attached"
            boot="-boot n"
        else
            bd=$(blkid -U 82c62bdc-a181-407b-8f73-2987c969ac3d  | sed -e "s/[0-9]\+//g")
            boot="-drive file=$bd,cache=none,if=virtio"
            echo "iscsi boot is $bd!"
        fi
    fi
fi

ulimit -l unlimited

#export PATH=$PATH:/sbin:/usr/sbin:/usr/local/sbin
#sudo chmod 777 /dev/kvm
#sudo chmod 777 /dev/net/tun
#sudo /sbin/setcap cap_net_admin+ep /sbin/tunctl

sleep 1
sync
setcap cap_net_admin=ei $binary 
setcap cap_net_raw=ei $binary 
setcap cap_sys_admin=ei $binary 
setcap cap_net_admin=ep $binary 
setcap cap_net_raw=ep $binary 
setcap cap_sys_admin=ep $binary 

dir=$(echo $0 | sed -e "s/\(.*\/\)*.*/\1.\//g")


if [ $network -eq 1 ] ; then
    net="-netdev type=tap,vhost=on,id=hostnet0,script=${dir}/kvmifup.sh,downscript=${dir}/kvmifdown.sh -device virtio-net-pci,netdev=hostnet0,mac=00:16:3e:42:57:4d"
else
    net=""
fi

usb=" -usb -device usb-tablet"
usb=""

run=" $user -enable-kvm -machine accel=kvm,iommu=off -m $mem -smp 2 -nodefaults -nodefconfig -rtc base=utc -no-shutdown $net $usb -device virtio-balloon-pci $boot $trace"
