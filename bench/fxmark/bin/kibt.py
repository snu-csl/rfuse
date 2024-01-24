#!/usr/bin/env python3
import os
import sys
import subprocess
import optparse
from os.path import join
from functools import reduce

CUR_DIR     = os.path.abspath(os.path.dirname(__file__))

class KernelBackTrace(object):
    def __init__(self, ksrc, filename, verbose):
        self.ksrc     = os.path.abspath(ksrc)
        self.filename = os.path.abspath(filename)
        self.objname  = ".".join(self.filename.rsplit(".")[:-1]) + ".o"
        self.verbose  = verbose

    def print_inlined_backtrace(self, caller, callee):
        asm_file   = self._get_file_asm()
        asm_caller = self._get_func_asm(asm_file, caller)
        if self.verbose:
            for asm_line in asm_caller:
                print(asm_line)
        i = -1
        for (i, ibt) in enumerate(self._get_inlined_backtrace(asm_caller, callee)):
            print("--- %d-th inlined backtrace ---" % (i + 1))
            for bt in ibt:
                print(" %s" % bt);
        print(">>> %d inlined backtraces were found!" % (i + 1))

    def _get_file_asm(self):
        '''
        This is the only linux kernel dependent function.
        All the rest are gcc-dependent.
        See following link for kernel debugging tricks.
          - http://elinux.org/Kernel_Debugging_Tips
        '''
        self._sh('rm %s' % self.objname).wait()
        p = self._sh('cd %s && ' \
                     'make EXTRA_CFLAGS="-g -Wa,-a,-ad -fverbose-asm" %s' %
                     (self.ksrc, self.objname),
                     out=subprocess.PIPE, err=None)
        asm_file = []
        for l in p.stdout.readlines():
            asm_file.append( l.decode("utf-8").strip() )
        return asm_file

    def _get_func_asm(self, asm_file, func):
        asm_func = []
        is_in = False
        for asm_line in asm_file:
            # find the start of the target function
            if is_in == False:
                if self._get_func_name(asm_line) == func:
                    is_in = True
                else:
                    continue
            # now, we are in the target function
            asm_func.append(asm_line)
            # is it the end?
            if self._end_of_func(asm_line):
                break
        return asm_func

    def _get_inlined_backtrace(self, func_asm, callee):
        ibt = []
        is_in = False
        # backward search
        for asm_line in reversed(func_asm):
            # find the callee
            func = None
            if is_in == False:
                if self._get_callee(asm_line) == callee:
                    ibt.insert(0, callee)
                    is_in = True
                    continue
            (func, filename, line) = self._get_inlined_callee_info(asm_line)
            if not func:
                continue
            if is_in == False:
                if func.startswith(callee + "("):
                    is_in = True
                else:
                    continue
            # ok, we found a inlined function
            ibt.insert(0, "%s @%s:%s" % (func, filename, line))
            # does this inlining end?
            if self.filename == filename:
                # yield the current inlined call stack
                yield(ibt)
                # and reset control variables
                ibt = []
                is_in = False

    def _get_func_name(self, asm_line):
        tokens = asm_line.split()
        #  12321                   .globl vfs_rename
        if len(tokens) == 3 and tokens[1] == ".globl":
            return tokens[2]
        # 259              	ext4_file_mmap:
        if len(tokens) == 2 and tokens[1][-1] == ":":
            return tokens[1][:-1]
        return None

    def _end_of_func(self, asm_line):
        tokens = asm_line.split()
        # 13415                   .cfi_endproc
        if len(tokens) == 2 and tokens[1] == ".cfi_endproc":
            return True
        return False

    def _get_callee(self, asm_line):
        tokens = asm_line.split()
        # 12521 40c9 E8000000      call kstrdup
        if len(tokens) == 5 and tokens[3] == "call":
            return tokens[4]
        # 113:/home/changwoo/workspace/research/linux/fs/ext4/file.c **** 		mutex_lock(aio_mutex);
        return None

    def _get_inlined_callee_info(self, asm_line):
        # 388:include/linux/dcache.h ****         spin_unlock(&dentry->d_lock);
        tokens = asm_line.split()
        if len(tokens) >= 3 and tokens[1] == "****":
            line_fname = tokens[0].split(":")
            callee = ' '.join(tokens[2:])
            return (callee, line_fname[1], line_fname[0])
        return (None, None, None)

    def _sh(self, cmd, out=None, err=None, verbose=False):
        if verbose:
            print(cmd)
        p = subprocess.Popen(cmd, shell=True, stdout=out, stderr=err)
        return p

if __name__ == "__main__":
    # option parsing
    parser = optparse.OptionParser()
    parser.add_option("--ksrc", help="kernel source directory")
    parser.add_option("--file", help="file path")
    parser.add_option("--caller",  help="caller function")
    parser.add_option("--callee",  help="callee function")
    parser.add_option('-v', '--verbose', dest="verbose",
                      default=False, action="store_true",)
    (opts, args) = parser.parse_args()

    # check options
    for opt in vars(opts):
        val = getattr(opts, opt)
        if val == None:
            print("Missing options: --%s" % opt)
            parser.print_help()
            exit(1)

    # run
    kbt = KernelBackTrace(opts.ksrc, opts.file, opts.verbose)
    kbt.print_inlined_backtrace(opts.caller, opts.callee)

'''
TODO XXX
- syscall calling convention: SYSC_xxx
'''
