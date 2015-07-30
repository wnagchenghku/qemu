#!/usr/bin/env bash
sudo virsh qemu-monitor-command cb-mrhines-SUSE-vm_5-mlg2 --hmp --cmd "info status"
sudo virsh qemu-monitor-command cb-mrhines-SUSE-vm_5-mlg2 --hmp --cmd "info migrate"
