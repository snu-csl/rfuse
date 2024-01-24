all : unit.o
	gcc -o unit -pthread unit.o

unit.o : unit.c
	gcc -c unit.c -o unit.o

clean :
	rm unit unit.o
