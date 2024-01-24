# -*- coding: utf-8 -*-

import sys
import os
import glob
import errno
import struct
from contextlib import contextmanager
import collections

__all__ = ("INITCPUINFO getCPUSet parseCpuinfo findCpuinfo expandCpuinfo "
           "parseRange strRange CPUBase NehalemCPU UnknownCPU "
           "getCPUClass".split())

INITCPUINFO = "/var/run/initcpuinfo"

def maybeInt(s):
    if s.isdigit():
        return int(s)
    return s

#
# CPU sets
#

def getCPUSet(name):
    return set(parseRange(file("/sys/devices/system/cpu/%s" % name).read()))

#
# /proc/cpuinfo
#

def parseCpuinfo(path):
    "Read a cpuinfo file and return [{field : value}]."

    res = []
    for block in file(path, "r").read().split("\n\n"):
        if len(block.strip()):
            res.append({})
            for line in block.splitlines():
                k, v = map(str.strip, line.split(":", 1))
                res[-1][k] = maybeInt(v)
            # Try to get additional info
            processor = res[-1]["processor"]
            nodefiles = glob.glob("/sys/devices/system/cpu/cpu%d/node*" % processor)
            if len(nodefiles):
                res[-1]["node"] = int(os.path.basename(nodefiles[0])[4:])

    return res

def findCpuinfo(paths = [INITCPUINFO, "/proc/cpuinfo"], needCPUs = None):
    "Find and return a cpuinfo list."

    for path in paths:
        if os.path.exists(path):
            cpuinfo = parseCpuinfo(path)
            break
    else:
        print >> sys.stderr, "No cpuinfo found (tried %s)" % ":".join(paths)
        sys.exit(1)

    if needCPUs is None:
        needCPUs = getCPUSet("present")
    if needCPUs.difference(set(int(cpu["processor"]) for cpu in cpuinfo)):
        print >> sys.stderr, ("Warning: Some processors are missing from %s.  "
                              "Are all processors online?" % path)
        if not os.path.exists(INITCPUINFO):
            print >> sys.stderr, ("Protip:  Add `cp /proc/cpuinfo %s' to "
                                  "/etc/rc.local." % INITCPUINFO)

    return cpuinfo

def expandCpuinfo(cpuinfo):
    "Add socket, coreid, and thread fields to cpuinfo."

    # {(socket, core id) : count}
    coreidCount = {}
    for cpu in cpuinfo:
        socket = cpu["physical id"]
        coreid = cpu["core id"]
        thread = coreidCount.get((socket, coreid), 0)
        coreidCount[(socket, coreid)] = thread + 1

        cpu["socket"] = socket
        cpu["coreid"] = coreid
        cpu["thread"] = thread
    return cpuinfo

#
# Range syntax
#

def parseRange(r):
    "Parse an integer sequence such as '0-3,8-11'.  '' is the empty sequence."

    if not r.strip():
        return []

    res = []
    for piece in r.strip().split(","):
        lr = piece.split("-")
        if len(lr) == 1 and lr[0].isdigit():
            res.append(int(lr[0]))
        elif len(lr) == 2 and lr[0].isdigit() and lr[1].isdigit():
            res.extend(range(int(lr[0]), int(lr[1]) + 1))
        else:
            raise ValueError("Invalid range syntax: %r" % r)
    return res

def strRange(cpus):
    spans = []
    for cpu in cpus:
        if spans and cpu == spans[-1][1] + 1:
            spans[-1][1] = cpu
        else:
            spans.append([cpu, cpu])
    return ",".join("%d" % s[0] if s[0] == s[1]
                    else ("%d,%d" % tuple(s) if s[1] == s[0] + 1
                          else "%d-%d" % tuple(s))
                    for s in spans)

#
# CPU objects
#

class CPUBase(object):
    PREFETCH_SETTINGS = None

    def __init__(self, cpu):
        self.__cpu = cpu

    @contextmanager
    def __openmsr(self, msr, mode):
        try:
            fd = os.open('/dev/cpu/%d/msr' % self.__cpu, mode)
        except EnvironmentError as e:
            msg = str(e)
            if e.errno == errno.EACCES:
                msg += ' (are you root?)'
            elif e.errno == errno.ENOENT:
                if os.path.exists('/dev/cpu/%d' % self.__cpu):
                    msg += ' (is the msr module loaded?)'
                else:
                    msg += ' (bad CPU number?)'
            print >>sys.stderr, msg
            sys.exit(1)
        try:
            # See man msr.  It's a weird interface
            os.lseek(fd, msr, os.SEEK_SET)
            yield fd
        finally:
            os.close(fd)

    def rdmsr(self, msr):
        with self.__openmsr(msr, os.O_RDONLY) as fd:
            return struct.unpack('Q', os.read(fd, 8))[0]

    def wrmsr(self, msr, val):
        with self.__openmsr(msr, os.O_WRONLY) as fd:
            os.write(fd, struct.pack('Q', val))


class NehalemPrefetchSettings(
        collections.namedtuple('NehalemPrefetchSettings',
                               'dcu_streamer dcu_ip mlc_spatial mlc_streamer')):
    DESC = '[1] Intel® 64 and IA-32 Architectures Optimization Reference Manual.'
    DOC = {'dcu_streamer':
           'L1 streaming prefetcher.'
           ' "This prefetcher, also known as the streaming prefetcher, is'
           ' triggered by an ascending access to very recently loaded data.'
           ' The processor assumes that this access is part of a streaming'
           ' algorithm and automatically fetches the next line." [1]',

           'dcu_ip':
           'L1 per-instruction stride prefetcher.'
           ' "This prefetcher keeps track of individual load instructions.'
           ' If a load instruction is detected to have a regular stride,'
           ' then a prefetch is sent to the next address which is the sum of'
           ' the current address and the stride. This prefetcher can prefetch'
           ' forward or backward and can detect strides of up to 2K bytes." [1]',

           'mlc_spatial':
           'L2/L3 adjacent line prefetcher.'
           ' "This prefetcher strives to complete every cache line fetched to'
           ' the L2 cache with the pair line that completes it to a 128-byte'
           ' aligned chunk." [1]',

           'mlc_streamer':
           'L2/L3 streaming prefetcher.'
           ' "This prefetcher monitors read requests from the L1 cache for'
           ' ascending and descending sequences of addresses. Monitored read'
           ' requests include L1 DCache requests initiated by load and store'
           ' operations and by the hardware prefetchers, and L1 ICache requests'
           ' for code fetch. When a forward or backward stream of requests is'
           ' detected, the anticipated cache lines are prefetched. Prefetched'
           ' cache lines must be in the same 4K page." [1]'}

    # Based on bits-767/boot/cfg/configure.nhm.common.cfg in
    # http://biosbits.org/downloads/bits-767.zip (and our own
    # experimentation in our BIOS).
    _MSR = 0x1a4
    _BITS = {'mlc_streamer': 0x01, 'mlc_spatial': 0x02,
             'dcu_streamer': 0x04, 'dcu_ip': 0x08}
    _MASK = ~0x0F

    @classmethod
    def from_msr(cls, val):
        return cls(**{k: not (val & bit) for k, bit in cls._BITS.items()})

    def to_msr(self):
        bits = 0
        for k, bit in self._BITS.items():
            if not getattr(self, k):
                bits |= bit
        return self._MASK, bits

class NehalemCPU(CPUBase):
    NAME = 'Nehalem'
    PREFETCH_SETTINGS = NehalemPrefetchSettings

    @staticmethod
    def check(vendor, family, model):
        return vendor == 'GenuineIntel' and family == 0x6 and \
            model in [0x1a, 0x1e, 0x1f, # Nehalem
                      0x25, 0x2c,       # Westmere
                      0x2e,             # Nehalem-EX
                      0x2f]             # Westmere-EX

    def get_prefetch_settings(self):
        return NehalemPrefetchSettings.from_msr(
            self.rdmsr(NehalemPrefetchSettings._MSR))

    def set_prefetch_settings(self, nps):
        if not isinstance(nps, NehalemPrefetchSettings):
            raise TypeError('%r is not a NehalemPrefetchSettings' % nps)
        mask, bits = nps.to_msr()
        val = (self.rdmsr(NehalemPrefetchSettings._MSR) & mask) | bits
        self.wrmsr(NehalemPrefetchSettings._MSR, val)

class UnknownCPU(CPUBase):
    NAME = 'Unknown CPU'
    @staticmethod
    def check(vendor, family, model):
        return True

def getCPUClass():
    cpus = findCpuinfo()
    vendor, family, model \
        = cpus[0]['vendor_id'], cpus[0]['cpu family'], cpus[0]['model']
    # XXX Lots of earlier models are documented in Intel SDM Vol 3.
    for CPUClass in [NehalemCPU, UnknownCPU]:
        if CPUClass.check(vendor, family, model):
            return CPUClass
