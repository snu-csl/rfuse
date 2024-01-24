#!/usr/bin/env python3
import os
import sys
import subprocess
import time
import operator
import pdb
from os.path import join
from functools import reduce

CUR_DIR     = os.path.abspath(os.path.dirname(__file__))

'''
# NOTE
- In order to use PerfMon.LEVEL_PERF_LOCK (i.e., perf lock record),
  lockdep and lockstat should be enabled in kernel configuration.

# PERF HOWTO
- http://www.brendangregg.com/perf.html
'''

class PerfMon(object):
    LEVEL_LOW                     = 0
    LEVEL_PERF_RECORD             = 1
    LEVEL_PERF_PROBE_SLEEP_LOCK_D = 2
    LEVEL_PERF_STAT               = 3
    LEVEL_PERF_PROBE_SLEEP_LOCK   = 998 # Well, it it not useful for fxmark.
    LEVEL_PERF_LOCK               = 999 # Well, it is mostly useless.
    CPU_STAT   = ["real", "user", "nice", "sys", "idle",
                  "iowait", "irq", "softirq", "steal", "guest"]
    SC_CLK_TCK = float(os.sysconf("SC_CLK_TCK"))
    PROBE_SLEEP_LOCK = [
        # - mutex
        "mutex_lock", "mutex_trylock", "mutex_lock_killable",
        #   "mutex_unlock",
        # - rwsem
        "down_read", "down_read_trylock", "down_write",
        "down_write_trylock", "downgrade_write",
        #   "up_read", "up_write",
        # - semaphore
        "down",
        #   "up",
        # - scheduler
        "io_schedule_timeout", # for wait_on_page_bit()
        "schedule",
        "preempt_schedule_common"
        #   "schedule_timeout",
    ]
    PERF_SAMPLE_RATE              = 1000

    # init
    def __init__(self, \
                 level = int(os.environ.get('PERFMON_LEVEL', "0")), \
                 ldir  =     os.environ.get('PERFMON_LDIR',  "."), \
                 lfile =     os.environ.get('PERFMON_LFILE', "_perfmon.stat" ),\
                 duration = 30):
        (self.LEVEL, self.DIR, self.FILE) = (level, ldir, lfile)
        self.duration = duration
        self.cpu_stat = os.path.normpath(
            os.path.join(self.DIR, self.FILE))

    # entry
    def start(self):
        if self.LEVEL >= PerfMon.LEVEL_LOW:
            self._cpu_stat_start()
        if self.LEVEL == PerfMon.LEVEL_PERF_RECORD:
            self._perf_record_start()
        if self.LEVEL == PerfMon.LEVEL_PERF_PROBE_SLEEP_LOCK:
            self._perf_probe_sleep_lock_start("")
        if self.LEVEL == PerfMon.LEVEL_PERF_STAT:
            self._perf_stat_start()
        if self.LEVEL == PerfMon.LEVEL_PERF_PROBE_SLEEP_LOCK_D:
            self._perf_probe_sleep_lock_start("%ax")
        if self.LEVEL == PerfMon.LEVEL_PERF_LOCK:
            self._perf_lock_record_start()

    def stop(self):
        try:
            if self.LEVEL == PerfMon.LEVEL_PERF_LOCK:
                self._perf_lock_record_stop()
            if self.LEVEL == PerfMon.LEVEL_PERF_RECORD:
                self._perf_record_stop()
            if self.LEVEL == PerfMon.LEVEL_PERF_PROBE_SLEEP_LOCK:
                self._perf_probe_sleep_lock_stop()
            if self.LEVEL == PerfMon.LEVEL_PERF_STAT:
                self._perf_stat_stop()
            if self.LEVEL == PerfMon.LEVEL_PERF_PROBE_SLEEP_LOCK_D:
                self._perf_probe_sleep_lock_stop()
            if self.LEVEL >= PerfMon.LEVEL_LOW:
                self._cpu_stat_stop()
        finally:
            return

    # cpu utilization
    def _cpu_stat_start(self):
        (ncpu, cpu_stat) = self._get_cpu_stat()
        cpu_stat_str = " ".join( map(lambda x: str(x), cpu_stat))
        with open(self.cpu_stat, "w") as fd:
            print(cpu_stat_str, file=fd)
            fd.flush()

    def _cpu_stat_stop(self):
        (ncpu, stat_stop) = self._get_cpu_stat()
        with open(self.cpu_stat, "r") as fd:
            stat_start = [float(p) for p in fd.readline().strip().split()]
        delta = list(map(operator.sub, stat_stop, stat_start))

        # calc. idle time
        total_cpu_time = sum(delta[1:])

        # calc cpu utlization
        delta.extend( list( map(lambda x: x/total_cpu_time * 100.0, delta[1:])))

        # column name string
        name = list( map(lambda x: "%s.sec" % x, PerfMon.CPU_STAT))
        name.extend( list( map(lambda x: "%s.util" % x, PerfMon.CPU_STAT[1:])))

        # write to file
        with open(self.cpu_stat, "w") as fd:
            print( " ".join(name), file=fd)
            print( " ".join( map(lambda x: "%g" % x, delta)), file=fd)
            fd.flush()

    def _get_cpu_stat(self):
        # According to Linux Documentation, 
        # /proc/stat is as follows;
        # - user: normal processes executing in user mode       
        # - nice: niced processes executing in user mode
        # - system: processes executing in kernel mode
        # - idle: twiddling thumbs
        # - iowait: waiting for I/O to complete
        # - irq: servicing interrupts
        # - softirq: servicing softirqs
        # - steal: involuntary wait
        # - guest: running a normal guest
        # - guest_nice: running a niced guest
        p = self._exec_cmd("sudo cat /proc/stat", subprocess.PIPE)
        ncpus = 0
        cpu_stat = []
        for l in p.stdout.readlines():
            l = l.decode("utf-8").strip()
            if l.startswith("cpu"):
                ncpus += 1
                if l.startswith("cpu "):
                    cpu_stat = [time.time()] + \
                               [int(p)/PerfMon.SC_CLK_TCK \
                                for p in l[4:].strip().split()]
        return (ncpus - 1, cpu_stat[:len(PerfMon.CPU_STAT)])

    # perf stat
    def _perf_stat_stop(self):
        pass

    def _perf_stat_start(self):
        perf_out = os.path.normpath(
                os.path.join(self.DIR, "%s.perf.stat.data" % self.FILE))
        self._exec_cmd("sudo perf stat -a -g -o %s sleep %s &" %
                (perf_out, self.duration))

    # perf record
    def _perf_record_stop(self):
        self._perf_stop()

    def _perf_record_start(self):
        perf_out = os.path.normpath(
            os.path.join(self.DIR, "%s.perf.data" % self.FILE))
        self._exec_cmd("sudo perf record -F %s -a -g -o %s &" %
                       (PerfMon.PERF_SAMPLE_RATE, perf_out))

    # perf probe sleepable locks
    def _perf_probe_cleanup(self):
        self._exec_cmd("sudo perf probe --del \'*\'")

    def _perf_probe_add_trace_points(self, arg0):
        self._perf_probe_cleanup()
        for prob in PerfMon.PROBE_SLEEP_LOCK:
            self._exec_cmd("sudo perf probe --add \'%s %s\'" % (prob, arg0))

    def _perf_probe_cmdline(self, arg0):
        probe_opt = ""
        for prob in PerfMon.PROBE_SLEEP_LOCK:
            probe_opt += " -e probe:%s" % prob
        if len(arg0) > 0:
            perf_out = os.path.normpath(
                os.path.join(self.DIR, "%s.perf.sleeplock.%s.data" %
                             (self.FILE, arg0[1:])))
        else:
            perf_out = os.path.normpath(
                os.path.join(self.DIR, "%s.perf.sleeplock.data" %
                             self.FILE))
        return ("sudo perf record %s -F %s -a -g -o %s &" %
                (probe_opt, PerfMon.PERF_SAMPLE_RATE, perf_out))

    def _perf_probe_sleep_lock_stop(self):
        self._perf_stop()
        self._perf_probe_cleanup()

    def _perf_probe_sleep_lock_start(self, arg0):
        self._perf_probe_add_trace_points(arg0)
        cmdline = self._perf_probe_cmdline(arg0)
        self._exec_cmd(cmdline)

    # perf lock record
    def _perf_lock_record_stop(self):
        self._exec_cmd("sudo sh -c \"echo 0 >/proc/sys/kernel/lock_stat\"")
        self._perf_stop()
        lock_stat = os.path.normpath(
            os.path.join(self.DIR, "%s.perf.lock_stat" % self.FILE))
        self._exec_cmd("sudo cp /proc/lock_stat %s" % lock_stat)

    def _perf_lock_record_start(self):
        self._exec_cmd("sudo sh -c \"echo 1 >/proc/sys/kernel/lock_stat\"")
        perf_out = os.path.normpath(
            os.path.join(self.DIR, "%s.perf.lock.data" % self.FILE))
        self._exec_cmd("sudo perf lock record -a -g -o %s &" % perf_out)

    def _perf_stop(self):
        with open("/dev/null", "a") as fd:
            self._exec_cmd("sudo kill -INT $(pgrep perf)", fd)

    def _exec_cmd(self, cmd, out=None):
        p = subprocess.Popen(cmd, shell=True, stdout=out, stderr=out)
        p.wait()
        return p

if __name__ == "__main__":
    # XXX. option parsing for level, ldir, and lfile

    # get command
    if len(sys.argv) != 2:
        exit(1)
    cmd = sys.argv[1]

    # run operation
    op = {"start":PerfMon.start,
          "stop":PerfMon.stop}
    def nop(x):
        exit(2)
    cmd_fn = op.get(cmd, nop)

    perfmon = PerfMon()
    cmd_fn(perfmon)
