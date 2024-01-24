all: NullFS

NullFS:
	gcc -Wall -Werror NullFS.c `pkg-config fuse3 --cflags --libs` -o NullFS

clean:
	rm -rf NullFS
