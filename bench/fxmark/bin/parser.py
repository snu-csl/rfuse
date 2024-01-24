#!/usr/bin/env python3
import os
import sys
import pdb

CUR_DIR     = os.path.abspath(os.path.dirname(__file__))

class Parser(object):
    def __init__(self):
        self.config = {}   # self.config['SYSTEM'] = 'Linux kernel ...'
        self.data   = {}   # self.data[ self.key ] = {self.schema:VALUE}
        self.key    = ()   # (mem, ext2, DWOM, 0002)
        self.schema = []   # ['ncpu', 'secs', 'works', 'works/sec']

    def parse(self, log_file):
        for l in self._get_line(log_file):
            parse_fn = self._get_parse_fn(l)
            parse_fn(l)

    def search_data(self, key_list = []):
        results = []
        nkey = self._norm_key(key_list)
        for key in self.data:
            if not self._match_key(nkey, key):
                continue
            rt = (key, self.data[key])
            results.append(rt)
        results.sort()
        return results

    def get_config(self, key):
        return self.config.get(key, None)

    def _match_key(self, key1, key2):
        for (k1, k2) in zip(key1, key2):
            if k1 == "*" or k2 == "*":
                continue
            if k1 != k2:
                return False
        return True

    def _get_line(self, pn):
        with open(pn) as fd:
            for l in fd:
                l = l.strip()
                if l is not "":
                    yield(l)
                    
    def _get_parse_fn(self, l):
        type_parser = {
            "###":self._parse_config,
            "##":self._parse_key,
            "#":self._parse_schema,
        }
        return type_parser.get(l.split()[0], self._parse_data)
    
    def _parse_config(self, l):
        kv = l.split(" ", 1)[1].split("=", 1)
        (key, value) = (kv[0].strip(), kv[1].strip())
        self.config[key] = value

    def _norm_key(self, ks):
        return tuple( map(lambda k: self._norm_str(k), ks))

    def _parse_key(self, l):
        ks = l.split(" ", 1)[1].split(":")
        self.key = self._norm_key(ks)

    def _parse_schema(self, l):
        self.schema = l.split()[1:]

    def _parse_data(self, l):
        for (d_key, d_value) in zip(self.schema, l.split()):
            d_kv = self.data.get(self.key, None)
            if not d_kv:
                self.data[self.key] = d_kv = {}
            d_kv[d_key] = d_value
        
    def _norm_str(self, s):
        try:
            n = int(s)
            return "%09d" % n
        except ValueError:
            return s

def __get_cpu_num(log, fs, bc, core, sp):
    test_log   = os.path.normpath(os.path.join(CUR_DIR, log))
    parser = Parser()
    parser.parse(test_log)
    key = ("mem", fs, bc, core)
    results = parser.search_data(key)
    for r in results:
        systime = r[1]['sys.sec']
        usertime = r[1]['user.sec']
        iotime = r[1]['iowait.sec']
        idletime = r[1]['idle.sec']
        if float(sp) == 0:
            print("user: %s\nsys:  %s\nidle: %s\nio:   %s\n" %
                (usertime, systime, idletime, iotime))
        else:
            synctime = float(sp) * float(systime) / 100.0
            fstime = float(systime) - synctime
            print("user:    %s\nfs-sys:  %s\nsync-sys:%s\nidle:    %s\nio:      %s\n" %
                (usertime, fstime, synctime, idletime, iotime))


def __get_performance(log, fs, bc):
    test_log = os.path.normpath(os.path.join(CUR_DIR, log))
    parser = Parser()
    parser.parse(test_log)
    key = ("mem", fs, bc, "*")
    r = parser.search_data(key)
    for i in range(len(r)):
        print("%s: %s" % (r[i][1]["ncpu"], float(r[i][1]["works/sec"])
            / float(r[0][1]["works/sec"])))


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: parser.py {logfile} {fs} {bc} {core} {syn %} -> for time info")
        print("Usage: parser.py p {logfile} {fs} {bc}")
        print("Example: ./parser.py p ../logs/optimus-mem-lk-4.2.log f2fs DWAL")
        print("Example: ./parser.py ../logs/optimus-mem-lk-4.2.log f2fs DWAL 80 85.7")
        exit(1)
   
    if sys.argv[1] == 'p':
        __get_performance(sys.argv[2], sys.argv[3], sys.argv[4])
        exit(0)
    __get_cpu_num(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
