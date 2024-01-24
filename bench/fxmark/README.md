# FxMark: Filesystem Multicore Scalability Benchmark
We analyze the manycore scalability of five widelydeployed file systems, namely, ext4, XFS, btrfs, F2FS, and tmpfs, by using our open source benchmark suite, FXMARK. FXMARK implements 19 microbenchmarks to stress specific components of each file system and includes three application benchmarks to measure the macroscopic scalability behavior. We observe that file systems are hidden scalability bottlenecks in many I/Ointensive applications even when there is no apparent contention at the application level.

FxMark is provided under the terms of the MIT license.

## Install & build
- Tested: Ubuntu 14.04

- Install filesystem-specific packages (e.g., mkfs.*)
~~~~~~{.sh}
$ bin/install-fs-tools.sh
~~~~~~

- Build FxMark
~~~~~{.sh}
$  make
~~~~~

- Clean FxMark
~~~~~{.sh}
$  make clean
~~~~~

## How to run

- Benchmark configuration
    - Set target media paths at bin/run-fxmark.py (e.g., Runner.LOOPDEV)
    - Set configuration for each run at bin/run-fxmark.py (i.e., run_config)

- Run benchmark
    - A log file will be created at 'logs' directory with starting time.
~~~~~{.sh}
$  bin/run-fxmark.py
~~~~~


## Plot results

### Scalability graphs
~~~~~{.sh}
$  bin/plotter.py --ty sc --log {log file} --out {output pdf file}
~~~~~

### CPU utilization graphs
~~~~~{.sh}
$  bin/plotter.py --ty util --log {log file} --ncore {# core} --out {output pdf file}
~~~~~

## Macro benchmarks

- Refer to our fxmark-apps branch in the [vbench repo](https://github.com/sslab-gatech/vbench/tree/fxmark-apps) for exim and rocksdb

## Authors

- Changwoo Min <changwoo@gatech.edu>
- Sanidhya Kashyap <sanidhya@gatech.edu>
- Steffen Maass <steffen.maass@gatech.edu>
- Woonhak Kang <woonhak.kang@gatech.edu>
- Taesoo Kim <taesoo@gatech.edu>

## Publications

- Paper on FxMark
```
Understanding Manycore Scalability of File Systems
Changwoo Min, Sanidhya Kashyap, Steffen Maass, Woonhak Kang, and Taesoo Kim
USENIX ATC 2016

@inproceedings{min:fxmark,
  title        = {{Understanding Manycore Scalability of File Systems}},
  author       = {Changwoo Min and Sanidhya Kashyap and Steffen Maass and Woonhak Kang and Taesoo Kim},
  booktitle    = {Proceedings of the 2016 USENIX Annual Technical Conference (ATC)},
  month        = jun,
  year         = 2016,
  address      = {Denver, CO},
}
```
