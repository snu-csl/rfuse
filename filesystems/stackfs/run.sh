#!/bin/bash

MOUNT_BASE="/mnt/RFUSE_EXT4"
MOUNT_POINT="/mnt/test"

DEVICE_NAME="/dev/nvme1n1"

mkdir -p ${MOUNT_BASE} ${MOUNT_POINT}
sudo sync

if [ "$1" == "ssd" ]
then
	sudo umount ${MOUNT_POINT} 
	sudo umount ${MOUNT_BASE} 
	sudo mkfs.ext4 -F -E lazy_itable_init=0,lazy_journal_init=0 ${DEVICE_NAME} 
	sudo mount ${DEVICE_NAME} ${MOUNT_BASE}
	sudo sync
	sudo echo 3 > /proc/sys/vm/drop_caches

	./StackFS_ll -r ${MOUNT_BASE} ${MOUNT_POINT} 
elif [ "$1" == "ssd-noclean" ]
then
	./StackFS_ll -r ${MOUNT_BASE} ${MOUNT_POINT} 
else
	echo ssd or noclean?
fi


