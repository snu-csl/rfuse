#!/bin/bash
PORT=3260
PORTAL=192.0.2.209
LUN=1
TARGET_NAME=foob
DBENCH=../../dbench

echo "Running dbench instance 1"
$DBENCH -B iscsi --iscsi-lun=$LUN --iscsi-port=$PORT --iscsi-target=$TARGET_NAME  --iscsi-portal=$PORTAL --warmup=2 -t 25 -c reserve_parallel_1.txt 1 &> output_1.txt &

sleep 2

echo "Running dbench instance 2"
$DBENCH -B iscsi --iscsi-lun=$LUN --iscsi-port=$PORT --iscsi-target=$TARGET_NAME  --iscsi-portal=$PORTAL --warmup=1 -t 25 -c reserve_parallel_2.txt 1  &> output_2.txt & 

echo "Waiting instances to finish"

sleep 60

cat output_1.txt | egrep failed\|ERROR  > /dev/null
if [ $? -eq 0 ]
then
	echo "the test Failed..."
	echo "Instance 1 result"
	echo "-----------------"
	cat output_1.txt | egrep failed\|ERROR
	echo
	echo "Instance 2 result"
	echo "-----------------"
	cat output_2.txt | egrep failed\|ERROR
else
	echo "The tests were a success..."
fi

rm output_1.txt output_2.txt
