#!/bin/bash

if [ "$1" == "first" ]
then
	sudo insmod ./fuse.ko
	echo first done
else
	sudo umount /sys/fs/fuse/connections
	sudo rmmod fuse
	sudo insmod ./fuse.ko
	echo done
fi
