#!/bin/bash

set -euo pipefail

FS_TYPE=("ext4" "rfuse" "fuse") 
FS_PATH="../../filesystems/stackfs"
DEVICE_NAME=("/dev/nvme1n1")

MOUNT_BASE="/mnt/RFUSE_EXT4"
MOUNT_POINT="/mnt/test"

function init_mount_point(){
	local fs=$1
	local dev=$2

	echo 3 > /proc/sys/vm/drop_caches

	if [ ${fs} == "ext4" ]; then
		set +euo pipefail
		echo "Unmount ext4..."
		sudo umount ${MOUNT_POINT}
		set -euo pipefail

		echo "Mount ext4..."
		sudo mkfs.ext4 -F -E lazy_itable_init=0,lazy_journal_init=0 ${dev} 	
		sudo mount ${dev} ${MOUNT_POINT} 
	
		sudo sync
	elif [ ${fs} == "fuse" ]; then
		set +euo pipefail
		echo "Unmount fuse-stackfs..."
		sudo umount ${MOUNT_POINT}

		echo "Unmount ext4..."
		sudo umount ${MOUNT_BASE}
		set -euo pipefail

		echo "Mount ext4..."
		sudo mkfs.ext4 -F -E lazy_itable_init=0,lazy_journal_init=0 ${dev} 	
		sudo mount ${dev} ${MOUNT_BASE} 

		echo "Mount fuse-stackfs..."
		pushd ${FS_PATH} 
		make clean
		make
		./StackFS_ll -r ${MOUNT_BASE} ${MOUNT_POINT} &	
		popd

		sudo sync
	elif [ ${fs} == "rfuse" ]; then
		set +euo pipefail
		echo "Unmount rfuse-stackfs..."
		sudo umount ${MOUNT_POINT}

		echo "Unmount ext4..."
		sudo umount ${MOUNT_BASE}
		set -euo pipefail

		echo "Mount ext4..."
		sudo mkfs.ext4 -F -E lazy_itable_init=0,lazy_journal_init=0 ${dev} 	
		sudo mount ${dev} ${MOUNT_BASE} 

		echo "Mount rfuse-stackfs..."
		pushd ${FS_PATH} 
		make clean
		make
		./StackFS_ll -r ${MOUNT_BASE} ${MOUNT_POINT} &	
		popd

		sudo sync
	else
		echo "Wrong file system type: ( ext4 | fuse | rfuse )"
		exit 1
	fi
}

function change_driver(){
	local fs=$1

	echo 3 > /proc/sys/vm/drop_caches

	if [ ${fs} == "ext4" ]; then
		echo "ext4 doesn't need driver"
	elif [ ${fs} == "fuse" ]; then
		echo "Change to fuse driver"
		pushd "../../lib/libfuse" 
		./libfuse_install.sh
		popd 

		pushd "../../driver/fuse"
		./fuse_insmod.sh
		popd
	elif [ ${fs} == "rfuse" ]; then
		echo "Change to rfuse driver"
		pushd "../../lib/librfuse" 
		./librfuse_install.sh
		popd 
		
		pushd "../../driver/rfuse"
		./rfuse_insmod.sh
		popd
	else
		echo "Wront file system type: ( ext4 | fuse | rfuse )"
		exit 1
	fi
}


echo 0 > /proc/sys/kernel/randomize_va_space 

mkdir -p logs ${MOUNT_BASE} ${MOUNT_POINT}

for fs in "${FS_TYPE[@]}"
do
	echo "file system: ${fs}"
	change_driver ${fs}

	for dev in "${DEVICE_NAME[@]}"
	do
		echo "file system: ${dev}"

		for ((i=0;i<1;i++))
		do
			mkdir -p logs/${dev}/${fs}/${i}
			echo 3 > /proc/sys/vm/drop_caches
		
			init_mount_point ${fs} ${dev}
			filebench -f workloads/fileserver.f | tee logs/${dev}/${fs}/${i}/fileserver.log 
		
			init_mount_point ${fs} ${dev}
			filebench -f workloads/webserver.f | tee logs/${dev}/${fs}/${i}/webserver.log 
		
			set +euo pipefail
			echo "Unmount mount point..."
			sudo umount ${MOUNT_POINT}
	
			echo "Unmount mount base..."
			sudo umount ${MOUNT_BASE}
			set -euo pipefail
		done
	done
done
