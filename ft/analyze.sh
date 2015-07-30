#!/usr/bin/env bash

if [ x"$1" == x ] ; then
      echo "need [rdmasource|rdmadest]"
      exit 1
fi

which=$1
shift

echo "error:"

grep -i -E "(bug\:|panic)" /tmp/migrate_output.$which.* | cut -d ":" -f 1 | sort | uniq | wc -l
echo "code errors:"
grep -i -E "(Early error|RDMA ERROR)" /tmp/migrate_output.$which.* | cut -d ":" -f 1 | sort | uniq | wc -l
echo "Responding:"
grep -i -E "EOF" /tmp/migrate_output.$which.* | cut -d ":" -f 1 | sort | uniq | wc -l
echo "total:"
ls -1 /tmp/migrate_output.$which.* | wc -l
