# Artifact Claims

### Notes

* We evaluated RFUSE with StackFS on PCIe Gen4 NVMe device with 80 cores. For machines with older PCIe generation device and the small number of cores, the benchmarks may not show similar results we present in the paper, but we believe the overall trends should be similar. 


### 1. FIO performance (Section 4.3.1)

**Claims**: 
* For sequential I/O operations, all frameworks and EXT4 show similar throughput due to the aid of page cache in the kernel. 

* For random I/O operations, RFUSE demonstrates higher throughput than FUSE due to the hybrid polling mechanism in reducing context switch and wake-up overhead. 


**Expected results**: 
* In Figure 8 (a) and (b), FUSE and RFUSE performs similarly to EXT4.

* In Figure 8 (c) and (d), RFUSE outperforms FUSE and show comparable throught to EXT4. 

### 2. I/O Scalability (Section 4.3.2)

**Claims**: 

* RFUSE scales well for common data operations due to its utilization of per-core ring channels.

**Expected results**: 

* In Figure 10, RFUSE scales better than FUSE, especially on random read operations (Figure 10 (d)). 

### 3. Metadata Operation Scalability (Section 4.3.3)

**Claims**: 

* RFUSE scales well for common metadata operations due to enhancing the parallelism of metadata operations and eliminating inter-NUMA accesses.

* For MRPL, MRPM and MRPH workloads, all frameworks and EXT4 shows similar scalability due to the aid of dcache in the kernel. 

**Expected results**: 

* In Figure 11, RFUSE scales better than FUSE for most of metadata operations.

* In Figure 11 (g)-(i), all frameworks and EXT4 illustrate similar scalability. 

### 4. Macro-benchmarks (Section 4.4)

**Claims**: 

* For filebench macro workloads, RFUSE outperforms FUSE and shows performance comparable to EXT4, which indicate that RFUSE is well-suited for handling a mixed set of operations.


**Expected results**: 

* In Figure 12, RFUSE outperforms FUSE and shows performance comparable to EXT4.

### 5. Latency Breakdown (Section 4.2)

**Claims**: 
* RFUSE demonstrates shorer latency than FUSE on NullFS due to reduction of communication overheads. 


**Expected results**: 
* Compared to Figure 2 and Figure 7, a wake-up overhead on RFUSE is shorter than FUSE.

* Compared to Figure 2 and Figure 7, a path traversal latency on RFUSE is shorter than FUSE since RFUSE eliminates the need for context switchs when processing requests and results.

 
