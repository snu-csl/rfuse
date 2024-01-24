# Experiment Guide

This is guideline for reproducing results mentioned in the paper from the scratch. This guideline assumes the use of a machine equipped with an additional storage device, excluding the root device.
For claims and expectations of the artifact, please refer to [here](claims.md).

We recommend to use root account or root-previleged user account to avoid unintentional permission denied error. We do not include EXTFUSE in the evaluation as the EXTFUSE shows similar (even lower) performance for the benchmarks.

### 0. Before running benchmarks
* **Before performing each benchmarks, make sure that base device for StackFS and any user-level filesystem is not mounted on a mount point.** 
* For most of benchmarks below, we prepared convenience scripts (named ```driver.sh```) that will evaluate performance of FUSE, RFUSE and EXT4. The scripts have variables that may have to be configured in advance (most of them don't need to configured except ```DEVICE_NAME```). 
Please check them before running each benchmarks.

  Example (```fio/driver.sh```):
    ```
    FS_TYPE=("ext4", "rfuse", "fuse")           # Frameworks (and EXT4) that want to run benchmark
    FS_PATH="../../filesystems/stackfs"         # Path of StackFS binary
    DEVICE_NAME="/dev/nvme1n1"                  # Base device which is used for StackFS

    MOUNT_BASE="/mnt/RFUSE_EXT4"                # Mount point of the base device
    MOUNT_POINT="/mnt/test"                     # Mount point of StackFS
    ```

* The scripts do not automatically build kernel driver of FUSE and RFUSE. Please build them before running the benchmarks.
    ```
    # (fuse kernel driver)
    $ cd driver/fuse
    $ make

    # (rfuse kernel driver)
    $ cd driver/rfuse
    $ make
    ```

* Execution logs will be stored under the top directory of each benchmarks. 
### 1. fio (Figure 8)

We have prepared the fio scripts to evaluate the throughput of FUSE, RFUSE with StackFS and EXT4. 

1\) Run fio benchmark script 
```
$ cd bench/fio
$ ./driver.sh
```

### 2. scale_fio (Figure 10)

We have prepared the scale_fio scripts to evaluate the I/O scalability of FUSE, RFUSE (with StackFS) and EXT4. 

1\) Run scale_fio benchmark script 
```
$ cd bench/scale_fio
$ ./driver.sh
```

### 3. fxmark (Figure 11)

We have prepared fxmark to evaluate the metadata operation scalability of FUSE and RFUSE. Since fxmark automatically detects the number of cores in a machine and runs experiment based on its core count, a granularity of core count may differ from what we show in Figure 11.
Each execution step outputs the results in the form below:
```
# ncpu secs works works/sec real.sec user.sec nice.sec sys.sec idle.sec iowait.sec irq.sec softirq.sec steal.sec guest.sec user.util nice.util sys.util idle.util iowait.util irq.util softirq.util steal.util guest.util
```
In Figure 11, we collected the (works/sec) value of each workloads.

1\) Build and install user library and kernel drivier of framework what you want to test

FUSE: 
```
# (libfuse)
$ cd lib/libfuse
$ ./libfuse_install.sh
	
# (fuse kernel driver)
$ cd driver/fuse
$ make 
$ ./fuse_insmod.sh first      # (if insmod the driver first time after reboot)
$ ./fuse_insmod.sh            # (if the driver is already insmoded)
```

RFUSE: 
```
# (librfuse)
$ cd lib/librfuse
$ ./librfuse_install.sh
	
# (rfuse kernel driver)
$ cd driver/rfuse
$ make 
$ ./rfuse_insmod.sh first      # (if insmod the driver first time after reboot)
$ ./rfuse_insmod.sh            # (if the driver is already insmoded)
```

2\) Build StackFS
```
$ cd filesystems/stackfs
$ make
```

3\) Build fxmark  
```
$ cd bench/fxmark
$ make
```

4\) Run fxmark script
```
$ cd bin
$ ./run-fxmark.py
```

### 4. filebench (Figure 12)
1\) Build and install filebench 
Move to bench/filebench/src and follow steps mentioned in [Filebench Installation](filebench/src/README).

2\) Run filebench script 
```
$ cd bench/filebench 
$ ./driver.sh
```

3\) Known Issues of filebench

* Filebench warns and recommends to disalble virtual address space randomization to provide stable filebench runs. If this feature is enabled, you may get ```Unexpected Process termination Code 3``` error. Our benchmark script disables this feature in advance when the script starts, but if you encount related error, please turn off it manually. 
    ```
    echo 0 > /proc/sys/kernel/randomize_va_space
    ```
    
* Since the number of files used in workload script is not small, the script could return ```out of shared memory``` error if you run it with pre-installed default filebench. This is because of the small size of ```struct filebench_shm_t``` in filebench source code. The source code preapared in ```bench/filebench/src``` have been fixed this issue, so please use that code to get stable results.

### 5. Latency breakdown (Figure 2 and Figure 7)

We evaluate latency of single CREATE operations and breakdown its latency on FUSE and RFUSE in Figure 2 and Figure 7, respectively. The unit test performs single creat() operation on a mount point. In the library and kernel driver, they print timestamps at each breakdown points. For description of each breakdown points, please read comments on top of ```fuse/dev.c``` and ```rfuse/rfuse_dev.c```. 

1\) Build and install user-level library and kernel driver in Debug mode
   
* FUSE and RFUSE print timestamps of each breakdown point only in debug mode. Please build library and driver using debug options. We prepared the compiler configurations in each build scripts. See ```driver/rfuse/Makefile``` line 6 and ```lib/librfuse/meson.build``` line 77 (same file in FUSE).

2\) Mount NullFS 
```
$ cd filesystems/nullfs
$ make
$ ./run.sh
```

3\) Build unit test 
```
$ cd bench/unit
$ make
```

4\) Run unit test and get timestamp results
```
$ ./unit 1
```

[Expected Outputs](unit/unit_output.md)

5\) Calculate the latency between each timestamps
