#!/usr/bin/env bash

if [ $0 != "-bash" ] ; then
        pushd `dirname "$0"` 2>&1 > /dev/null
fi
dir=$(pwd)
if [ $0 != "-bash" ] ; then
        popd 2>&1 > /dev/null
fi

if [ x"$1" == x ] ; then
	echo "need [rdmasource|rdmadest] "
	exit 1
fi
which=$1
shift

last=$(date +%s)
echo "looping $which"

rm -rf /tmp/migrate_last.$which
mkdir /tmp/migrate_last.$which
mv /tmp/migrate_output.$which.* /tmp/migrate_last.$which

source ${dir}/common_config.sh

function pb {
    if [ $which == "rdmasource" ] ; then
        if [ $mc -eq 1 ] && [ "x$mc_net_disable" == "xoff" ]; then
            if [ ! -e /sys/class/net/ifb0 ] ; then
                echo "ifb kernel module is not loaded or configured. bailing."
                exit 1
            fi
        fi
        blowawaypids primary.sh
        $(echo $0 | sed -e "s/\(.*\/\)*.*/\1.\//g")/primary.sh
    else
        $(echo $0 | sed -e "s/\(.*\/\)*.*/\1.\//g")/backup.sh
    fi
    if [ $? -gt 0 ] ; then
        echo "${which} failed ${proto} ${host} ${display}"
    fi
}

function nbd {
    if [ $which == "rdmabackup" ] ; then
        if [ ${mc_disk_disable} == "off" ] ; then
            echo "starting nbd server"
            ${dir}/qemu-monitor /tmp/devguest.dest nbd_server_start 0:6262
            ${dir}/qemu-monitor /tmp/devguest.dest nbd_server_add -w mc1 
        fi
    fi
}

if [ $gdb -eq 0 ] ; then
    (while true ; do 
        reset
        echo "qemu_loop is $qemu_loop"
        sleep 5
        (sleep 10 && nbd &)
        pb

        if [ "$qemu_loop" -eq 0 ] ; then
            echo "stopping now"
            break
        fi
    done &)
else
    while true ; do 
        reset
        (sleep 10 && nbd &)
        sleep 5
        pb
    done
    exit 1
fi

echo "attaching monitor"

while true ; do

    if [ $which == "rdmasource" ] ; then
        tport=5555
    else
        tport=5556
    fi

    while true ; do
        out="$(netstat -atnp | grep $tport)"
        if [ x"$out" != x ] ; then 
            echo "serial port is open. connecting..."
            break
        fi
        echo "serial port is closed, waiting..."
        sleep 5
    done

    telnet 127.0.0.1 $tport < "$(tty)" | tee /tmp/migrate_output.$which
    mv /tmp/migrate_output.$which /tmp/migrate_output.$which.$last
    lines="$(wc -l /tmp/migrate_output.${which}.${last} | cut -d " " -f 1)"
    if [ $lines -lt 8 ] ; then
        echo "nothing useful in file. skipping."
    else
        echo "lines: $lines"
        last=$(date +%s)
        if [ $which == "rdmasource" ] ; then
            if [ $mc -eq 1 ] ; then
                for num in $(seq $killwait -1 1); do 
                    echo "Waiting recovery for $num secs..."
                    sleep 1
                done
                echo "$evalwait more seconds..."
                sleep $evalwait 
                sleep 5
                echo "recovery over."
            else
                echo "MC not enabled. Moving to next migration"
            fi
        else
            echo "No MC wait on destination. Skipping"
        fi
        if [ $qemu_loop -eq 0 ] ; then
            echo "Stopping now."
            break
        fi
    fi
    echo "telnet broken on $last, trying again in 5..."
    sleep 5
done

