#!/usr/bin/env python3

import os
import subprocess
import optparse

CUR_DIR = os.path.abspath(os.path.dirname(__file__))

''' This is used for generating stdio output of multiple files in
    a directory or a single file. Only specify the directory and
    it will generate the file there itself.
'''

class PerfStdio(object):
    def __init__(self, dir_name, out_dir_name = None):
        self.dir_name = os.path.join(CUR_DIR, dir_name)
        if out_dir_name is None:
            self.out_dir_name = self.dir_name
        else:
            self.out_dir_name = self.out_dir_name
        self.out_dir_name = os.path.join(CUR_DIR, self.out_dir_name)

    def gen_stdio(self):
        if (not os.path.isdir(self.out_dir_name)):
            os.mkdir(self.out_dir_name)
        for f in os.listdir(self.dir_name):
            if f.endswith(("data")):
                print("parsing %s ..." % f)
                stdio_filename = f + ".stdio.txt"
                cmd_arg = "sudo perf report -f --stdio -i %s" % ( \
                        os.path.join(self.dir_name, f))
                out_fd = open(os.path.join(self.out_dir_name, stdio_filename), "w")
                self._exec_cmd(cmd_arg, out_fd)
                out_fd.close()
                print("parsing %s ... done" % f)

    def _exec_cmd(self, cmd, out=subprocess.STDOUT):
        p = subprocess.Popen(cmd, shell=True,
                stdout=out, stderr=subprocess.PIPE)
        p.wait()
        if out is not subprocess.STDOUT:
            out.flush()
        return p

def __print_usage():
    print("Usage: perfstdio.py --dir [directory]")
    print("                    --out [output directory]")


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("--dir",  help="perf data directory")
    parser.add_option("--out",  help="perf stdio output directory")
    (opt, args) = parser.parse_args()

    if opt.dir is None:
        __print_usage()
        exit(1)

    perfstdio = PerfStdio(opt.dir, opt.out)
    perfstdio.gen_stdio()
