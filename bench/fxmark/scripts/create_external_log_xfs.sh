# SPDX-License-Identifier: MIT
#!/bin/bash

# $1-> directory to mount first partition
# $2-> directory to mount log partition
# $3-> mount on which we will do the experiment

TMP=$1
TMP1=$2
XFS=$3


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

sudo mkfs.xfs -f /dev/loop2 -l logdev=/dev/loop3,size=1024m

sudo mount -o logdev=/dev/loop3 /dev/loop2 $XFS 
