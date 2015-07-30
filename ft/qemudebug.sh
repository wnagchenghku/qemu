#!/usr/bin/env bash
gdb /home/mrhines/qemu/x86_64-softmmu/qemu-system-x86_64 --pid $(pgrep -f cb-mrhines-SUSE-vm_5-mlg2) -ex "handle SIGUSR2 noprint" -ex "" -ex "continue"
