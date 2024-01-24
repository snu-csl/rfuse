set mode quit alldone
set $dir=/mnt/test
set $nfiles=1250000
set $meandirwidth=20
set $nthreads=100
set $size1=16k

define fileset name=bigfileset, path=$dir, size=$size1, entries=$nfiles, dirwidth=$meandirwidth, prealloc=100
define fileset name=logfiles, path=$dir, size=$size1, entries=1, dirwidth=$meandirwidth, prealloc

define process name=webserver,instances=1
{
        thread name=webserverthread,memsize=10m,instances=$nthreads
        {
                flowop openfile name=openfile1,filesetname=bigfileset,fd=1
                flowop readwholefile name=readfile1,fd=1,iosize=1m
                flowop closefile name=closefile1,fd=1
                flowop openfile name=openfile2,filesetname=bigfileset,fd=1
                flowop readwholefile name=readfile2,fd=1,iosize=1m
                flowop closefile name=closefile2,fd=1
                flowop openfile name=openfile3,filesetname=bigfileset,fd=1
                flowop readwholefile name=readfile3,fd=1,iosize=1m
                flowop closefile name=closefile3,fd=1
                flowop openfile name=openfile4,filesetname=bigfileset,fd=1
                flowop readwholefile name=readfile4,fd=1,iosize=1m
                flowop closefile name=closefile4,fd=1
                flowop openfile name=openfile5,filesetname=bigfileset,fd=1
                flowop readwholefile name=readfile5,fd=1,iosize=1m
                flowop closefile name=closefile5,fd=1
                flowop openfile name=openfile6,filesetname=bigfileset,fd=1
                flowop readwholefile name=readfile6,fd=1,iosize=1m
                flowop closefile name=closefile6,fd=1
                flowop openfile name=openfile7,filesetname=bigfileset,fd=1
                flowop readwholefile name=readfile7,fd=1,iosize=1m
                flowop closefile name=closefile7,fd=1
                flowop openfile name=openfile8,filesetname=bigfileset,fd=1
                flowop readwholefile name=readfile8,fd=1,iosize=1m
                flowop closefile name=closefile8,fd=1
                flowop openfile name=openfile9,filesetname=bigfileset,fd=1
                flowop readwholefile name=readfile9,fd=1,iosize=1m
                flowop closefile name=closefile9,fd=1
                flowop openfile name=openfile10,filesetname=bigfileset,fd=1
                flowop readwholefile name=readfile10,fd=1,iosize=1m
                flowop closefile name=closefile10,fd=1
                flowop appendfilerand name=appendlog,filesetname=logfiles,iosize=16k,fd=2
                flowop finishoncount name=finish, value=8000000
                #so that all the above operations will together complete 8 M(SSD) ops 
        }
}
create files
system "sync"

run 
