# SPDX-License-Identifier: MIT
#!/bin/bash

# $1-> directory to mount first partition
# $2-> directory to mount log partition
# $3-> mount on which we will do the experiment

TMP=$1
TMP1=$2
EXT4=$3


if [[ "$#" -ne 3 ]]
then
	echo "usage: $0 <Directory 1> <Directory 2> <Directory 3>"
	exit
fi

sudo mount -t tmpfs -o mode=0777,size=32G none $TMP
sudo mount -t tmpfs -o mode=0777,size=1G none $TMP1

dd if=/dev/zero of=$TMP/disk.img bs=1G count=102400
dd if=/dev/zero of=$TMP1/disk.img bs=1G count=102400

sudo losetup /dev/loop2 $TMP/disk.img
sudo losetup /dev/loop3 $TMP1/disk.img

sudo mke2fs -O journal_dev /dev/loop3
sudo mke2fs -t ext4 /dev/loop2
sudo tune2fs -O ^has_journal /dev/loop2
sudo tune2fs -o journal_data -j -J device=/dev/loop3 /dev/loop2

sudo mount -t ext4 /dev/loop2 $EXT4
