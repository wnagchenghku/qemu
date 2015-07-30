#!/usr/bin/env bash

dir=$(echo $0 | sed -e "s/\(.*\/\)*.*/\1.\//g")
source $dir/common_config.sh

function clean_up {
    trap - SIGINT
    if [ $mc -eq 1 ] ; then
        echo "Terminating primary upon CTRL-C"
        blowawaypids primary.sh
        blowawaypids rdmaprimary
        for num in $(seq $killwait -1 1); do 
            echo "Waiting recovery for $num secs..."
            sleep 1
        done
        echo "recovery over."
        blowawaypids rdmasource
        trap clean_up SIGINT
    else
        echo "CTRL-C exiting."
        exit 1
    fi
}

trap clean_up SIGINT

sshawaypids rdmabackup ${host}
sshawaypids backup.sh ${host}
sshawaypids rdmadest ${host}
sleep 5

while true ; do 
    reset

    $(echo $0 | sed -e "s/\(.*\/\)*.*/\1.\//g")/manual_replicate.sh $host $proto $display 

    if [ $? -eq 0 ] ; then
        (ssh -t -t -i ${dir}/klab_id_rsa.${arch} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $username@${dest} -f "while true ; do date > /tmp/tmpdate; sudo write root ${terminal} < /tmp/tmpdate; sleep 1; done" &)
    fi

    if [ $migrate_loop -eq 0 ] ; then
        echo "Stopping now."
        break
    fi

    for num in $(seq $evalwait -1 1); do 
        echo "evaluate situation $num..."
        sleep 1
    done

    if [ $migrate_loop -gt 0 ] ; then
        sshawaypids rdmabackup ${host}
        sshawaypids backup.sh ${host}
        sshawaypids rdmadest ${host}
    fi
done
