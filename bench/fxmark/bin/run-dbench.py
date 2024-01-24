#!/usr/bin/env python3
import os
import sys
import signal
import subprocess
import datetime
import tempfile
import optparse
import time
import pdb
from os.path import join

CUR_DIR = os.path.abspath(os.path.dirname(__file__))

class DBench(object):
    WORKLOAD_DIR = os.path.normpath(os.path.join(CUR_DIR, "dbench-workloads"))
    PERF_STR = "Throughput"

    def __init__(self, type_, ncore_, duration_, root_,
                 profbegin_, profend_, proflog_):
        self.config = None
        self.bench_out = None
        # take configuration parameters
        self.workload = type_
        self.ncore = int(ncore_)
        self.duration = int(duration_)
        self.root = root_
        self.profbegin = profbegin_
        self.profend = profend_
        self.proflog = proflog_
        self.profenv = ' '.join(["PERFMON_LEVEL=%s" %
                                 os.environ.get('PERFMON_LEVEL', "x"),
                                 "PERFMON_LDIR=%s"  %
                                 os.environ.get('PERFMON_LDIR',  "x"),
                                 "PERFMON_LFILE=%s" %
                                 os.environ.get('PERFMON_LFILE', "x")])
        self.perf_msg = None

    def __del__(self):
        # clean up
        try:
            if self.config:
                os.unlink(self.config.name)
            if self.bench_out:
                os.unlink(self.bench_out.name)
        except:
            pass

    def run(self):
        # start performance profiling
        self._exec_cmd("%s %s" % (self.profenv, self.profbegin)).wait()
        # run dbench 
        self._run_dbench()
        # stop performance profiling
        self._exec_cmd("%s %s" % (self.profenv, self.profend)).wait()
        return 0

    def _run_dbench(self):
        with tempfile.NamedTemporaryFile(delete=False) as self.bench_out:
            cmd = "sudo dbench %s -t %s -c %s -D %s" % (self.ncore, self.duration, self.get_config(), self.root)
            p = self._exec_cmd(cmd, subprocess.PIPE)
            while True:
                for l in p.stdout.readlines():
                    self.bench_out.write("#@ ".encode("utf-8"))
                    self.bench_out.write(l)
                    l_str = str(l)
                    idx = l_str.find(DBench.PERF_STR)
                    if idx is not -1:
                        self.perf_msg = l_str[idx+len(DBench.PERF_STR):]
                if self.perf_msg:
                    break
            self.bench_out.flush()

    def report(self):
        # Throughput 640.759 MB/sec  32 clients  32 procs  max_latency=464.544 ms
        throughput = 0
        items = self.perf_msg.split()
        throughput = items[0]
        profile_name = ""
        profile_data = ""
        try:
            with open(self.proflog, "r") as fpl:
                l = fpl.readlines()
                if len(l) >= 2:
                    profile_name = l[0]
                    profile_data = l[1]
        except:
            pass
        # we don't have works for dbench..
        print("# ncpu secs works works/sec %s" % profile_name)
        print("%s %s %s %s %s" %
              (self.ncore, self.duration, 0, throughput, profile_data))

    def get_config(self):
        return os.path.normpath(os.path.join(DBench.WORKLOAD_DIR,
                                                        self.workload + ".txt"))

    def _exec_cmd(self, cmd, out=None):
        p = subprocess.Popen(cmd, shell=True, stdout=out, stderr=out)
        return p

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("--type", help="workload name")
    parser.add_option("--ncore", help="number of core")
    parser.add_option("--nbg", help="not used")
    parser.add_option("--duration", help="benchmark time in seconds")
    parser.add_option("--root", help="benchmark root directory")
    parser.add_option("--profbegin", help="profile begin command")
    parser.add_option("--profend", help="profile end command")
    parser.add_option("--proflog", help="profile log path")
    (opts, args) = parser.parse_args()

    # check options
    for opt in vars(opts):
        val = getattr(opts, opt)
        if val == None:
            print("Missing options: %s" % opt)
            parser.print_help()
            exit(1)

    # run benchmark
    dbench = DBench(opts.type, opts.ncore, opts.duration, opts.root,
                          opts.profbegin, opts.profend, opts.proflog)
    rc = dbench.run()
    dbench.report()
    exit(rc)

