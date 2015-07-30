#!/usr/bin/env bash
sudo virsh qemu-monitor-command cb-mrhines-vm_99-was --hmp --cmd "migrate_set_speed 10g"
sudo virsh qemu-monitor-command cb-mrhines-vm_99-was --hmp --cmd "migrate -d kemari:tcp:192.168.0.1:4020"
