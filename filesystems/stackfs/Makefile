all: StackFS_ll

StackFS_ll:
	gcc -Wall StackFS_LowLevel.c `pkg-config fuse3 --cflags --libs` -o StackFS_ll

clean:
	rm -rf StackFS_ll
