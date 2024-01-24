# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the FUSE filesystem.
#

# Uncomment below line to compile with debug option 
# ccflags-y += -DDEBUG

obj-m += fuse.o

fuse-y := dev.o dir.o file.o inode.o control.o xattr.o acl.o readdir.o ioctl.o rfuse_dev.o rfuse_dir.o rfuse_inode.o rfuse_file.o rfuse_comp.o
fuse-$(CONFIG_FUSE_DAX) += dax.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
 
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
