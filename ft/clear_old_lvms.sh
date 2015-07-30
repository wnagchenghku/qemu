#!/usr/bin/env bash
if [ x"$(uname -a | grep xen)" != x ] ; then
	vms=$(xm list | grep cb-mrhines | cut -d " " -f 1)
else
	vms=$(virsh list --all | grep cb-mrhines | sed "s/ \+/ /g" | sed "s/^ //g" | cut -d " " -f 2)
fi

disks=$(ls -1 /dev/cb/cloudbench_*-cb-mrhines*)
dead_lvms=""

for disk in $disks ; do
	found=0
	for vm in $vms ; do
		file=$(echo $disk | sed "s/.*\/cloudbench_[a-z]\+-//g")
		if [ $file == $vm ] ; then
			echo "disk $file is running"
			found=1
			break
		fi
	done
	if [ $found -eq 0 ] ; then
		echo "lvm $disk not used. will destroy"
		dead_lvms="$dead_lvms $disk"
	fi

done

for dead in $dead_lvms ; do
	lvremove -f $dead
done
