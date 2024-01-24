#!/usr/bin/env python3
import os
import stat
import sys
import subprocess
import optparse
import math
import pdb
from parser import Parser

CUR_DIR     = os.path.abspath(os.path.dirname(__file__))

"""
# GNUPLOT HOWTO
- http://www.gnuplotting.org/multiplot-placing-graphs-next-to-each-other/
- http://stackoverflow.com/questions/10397750/embedding-multiple-datasets-in-a-gnuplot-command-script
- http://ask.xmodulo.com/draw-stacked-histogram-gnuplot.html
"""

class Plotter(object):
    def __init__(self, log_file):
        # config
        self.UNIT_WIDTH  = 2.3
        self.UNIT_HEIGHT = 2.3
        self.PAPER_WIDTH = 7   # USENIX text block width
        self.EXCLUDED_FS = ()  # ("tmpfs")
        self.CPU_UTILS = ["user.util",
                          "sys.util",
                          "idle.util",
                          "iowait.util"]
        self.UNIT = 1000000.0

        # init.
        self.log_file = log_file
        self.parser = Parser()
        self.parser.parse(self.log_file)
        self.config = self._get_config()
        self.ncore = int(self.parser.get_config("PHYSICAL_CHIPS")) * \
                     int(self.parser.get_config("CORE_PER_CHIP"))
        self.out_dir  = ""
        self.out_file = ""
        self.out = 0

    def _get_config(self):
        all_config = []
        config_dic = {}
        for kd in self.parser.search_data():
            key = kd[0]
            for (i, k) in enumerate(key):
                try:
                    all_config[i]
                except IndexError:
                    all_config.append(set())
                all_config[i].add(k)
        for (i, key) in enumerate(["media", "fs", "bench", "ncore", "iomode"]):
            config_dic[key] = sorted(list(all_config[i]))
        return config_dic

    def _gen_log_info(self):
        log_info = self.parser.config
        print("# LOG_FILE = %s" % self.log_file, file=self.out)
        for key in log_info:
            print("# %s = %s" % (key, log_info[key]), file=self.out)
        print("", file=self.out)

    def _get_pdf_name(self):
        pdf_name = self.out_file
        outs = self.out_file.split(".")
        if outs[-1] == "gp" or outs[-1] == "gnuplot":
            pdf_name = '.'.join(outs[0:-1]) + ".pdf"
        pdf_name = os.path.basename(pdf_name)
        return pdf_name

    def _get_fs_list(self, media, bench, iomode):
        data = self.parser.search_data([media, "*", bench, "*", iomode])
        fs_set = set()
        for kd in data:
            fs = kd[0][1]
            if fs not in self.EXCLUDED_FS:
                fs_set.add(fs)
        #remove tmpfs - to see more acurate comparision between storage fses
#        fs_set.remove("tmpfs");
        return sorted(list(fs_set))

    def _gen_pdf(self, gp_file):
        subprocess.call("cd %s; gnuplot %s" %
                        (self.out_dir, os.path.basename(gp_file)),
                        shell=True)

    def _plot_header(self):
        n_unit = len(self.config["media"]) * len(self.config["bench"])
        n_col = min(n_unit, int(self.PAPER_WIDTH / self.UNIT_WIDTH))
        n_row = math.ceil(float(n_unit) / float(n_col))
        print("set term pdfcairo size %sin,%sin font \',10\'" %
              (self.UNIT_WIDTH * n_col, self.UNIT_HEIGHT * n_row),
              file=self.out)
        print("set_out=\'set output \"`if test -z $OUT; then echo %s; else echo $OUT; fi`\"\'"
              % self._get_pdf_name(), file=self.out)
        print("eval set_out", file=self.out)
        print("set multiplot layout %s,%s" % (n_row, n_col), file=self.out)

    def _plot_footer(self):
        print("", file=self.out)
        print("unset multiplot", file=self.out)
        print("set output", file=self.out)


    def _plot_sc_data(self, media, bench, iomode):
        def _get_sc_style(fs):
            return "with lp ps 0.5"

        def _get_data_file(fs):
            return "%s:%s:%s:%s.dat" % (media, fs, bench, iomode)

        # check if there are data
        fs_list = self._get_fs_list(media, bench, iomode)
        if fs_list == []:
            return

        # gen sc data files
        for fs in fs_list:
            data = self.parser.search_data([media, fs, bench, "*", iomode])
            if data == []:
                continue
            data_file = os.path.join(self.out_dir, _get_data_file(fs))
            with open(data_file, "w") as out:
                print("# %s:%s:%s:%s:*" % (media, fs, bench, iomode), file=out)
                for d_kv in data:
                    d_kv = d_kv[1]
                    if int(d_kv["ncpu"]) > self.ncore:
                        break
                    print("%s %s" %
                          (d_kv["ncpu"], float(d_kv["works/sec"])/self.UNIT),
                          file=out)
        
        # gen gp file
        print("", file=self.out)
        print("set title \'%s:%s:%s\'" % (media, bench, iomode), file=self.out)
        print("set xlabel \'# cores\'", file=self.out)
        print("set ylabel \'%s\'" % "M ops/sec", file=self.out)

        fs = fs_list[0]
        print("plot [0:][0:] \'%s\' using 1:2 title \'%s\' %s"
              % (_get_data_file(fs), fs, _get_sc_style(fs)),
              end="", file=self.out)
        for fs in fs_list[1:]:
            print(", \'%s\' using 1:2 title \'%s\' %s"
                  % (_get_data_file(fs), fs, _get_sc_style(fs)),
                  end="", file=self.out)
        print("", file=self.out)

    def _plot_util_data(self, media, ncore, bench, iomode):
        print("", file=self.out)
        print("set grid y", file=self.out)
        print("set style data histograms", file=self.out)
        print("set style histogram rowstacked", file=self.out)
        print("set boxwidth 0.5", file=self.out)
        print("set style fill solid 1.0 border -1", file=self.out)
        print("set ytics 10", file=self.out)
        print("", file=self.out)
        print("set title \'%s:%s:*:%s:%s\'" % (media,bench, ncore, iomode), file=self.out)
        print("set xlabel \'\'", file=self.out)
        print("set ylabel \'CPU utilization\'", file=self.out)
        print("set yrange [0:100]", file=self.out)
        print("set xtics rotate by -45", file=self.out)
        print("set key out horiz", file=self.out)
        print("set key center top", file=self.out)
        print("", file=self.out)

        '''
        #    user.util sys.util idle.util iowait.util
        ext2 20        45       35        0
        xfs  10        50       40        0
        '''
        print("# %s:*:%s:%s" % (media, bench, ncore), file=self.out)
        print("plot \'-\' using 2:xtic(1) title \'%s\'"
              % self.CPU_UTILS[0].split('.')[0], end="", file=self.out)
        for (i, util) in enumerate(self.CPU_UTILS[1:]):
            print(", \'\' using %s title \'%s\'"
                  % (i+3, util.split('.')[0]),
                  end="", file=self.out)
        print("", file=self.out)

        fs_list = self._get_fs_list(media, bench, iomode)
        for _u in self.CPU_UTILS:
            print("  # %s" % self.CPU_UTILS, file=self.out)
            for fs in fs_list:
                data = self.parser.search_data([media, fs, bench, str(ncore), iomode])
                if data is None:
                    continue
                d_kv = data[0][1]

                print("  \"%s\"" % fs, end="", file=self.out)
                for util in self.CPU_UTILS:
                    print(" %s" % d_kv[util], end="", file=self.out)
                print("", file=self.out)
            print("e", file=self.out)

    def plot_sc(self, out_dir):
        self.out_dir  = out_dir
        subprocess.call("mkdir -p %s" % self.out_dir, shell=True)
        self.out_file = os.path.join(self.out_dir, "sc.gp")
        self.out = open(self.out_file, "w")
        self._gen_log_info()
        self._plot_header()
        for media in self.config["media"]:
            for bench in self.config["bench"]:
                for iomode in self.config["iomode"]:
                    self._plot_sc_data(media, bench, iomode)
        self._plot_footer()
        self.out.close()
        self._gen_pdf(self.out_file)

    def plot_util(self, ncore, out_dir):
        self.out_dir  = out_dir
        subprocess.call("mkdir -p %s" % self.out_dir, shell=True)
        self.out_file = os.path.join(self.out_dir, ("util.%s.gp" % ncore))
        self.out = open(self.out_file, "w")
        self._gen_log_info()
        self._plot_header()
        for media in self.config["media"]:
            for bench in self.config["bench"]:
                for iomode in self.config["iomode"]:
                    self._plot_util_data(media, ncore, bench, iomode)
        self._plot_footer()
        self.out.close()
        self._gen_pdf(self.out_file)

    def _gen_cmpdev_for_bench(self, ncore, bench):
        # for each file system
        print("## %s" % bench, file=self.out)
        print("# fs ssd-rel hdd-rel mem ssd hdd", file=self.out)
        for fs in self._get_fs_list("*", bench):
            data = self.parser.search_data(["*", fs, bench, "%s" % ncore])
            dev_val = {}
            for d_kv in data:
                dev = d_kv[0][0]
                dev_val[dev] = d_kv[1]
            # XXX: ugly [[[
            if dev_val.get("mem", None) == None:
                print("WARNING: there is no %s:%s:%s:%s result." %
                      ("mem", fs, bench, ncore), file=sys.stderr)
                continue
            if dev_val.get("ssd", None) == None:
                print("WARNING: there is no %s:%s:%s:%s result." %
                      ("ssd", fs, bench, ncore), file=sys.stderr)
                continue
            if dev_val.get("hdd", None) == None:
                print("WARNING: there is no %s:%s:%s:%s result." %
                      ("hdd", fs, bench, ncore), file=sys.stderr)
                continue
            # fs ssd-rel hdd-rel mem ssd hdd 
            mem_perf = float(dev_val["mem"]["works/sec"])
            ssd_perf = float(dev_val["ssd"]["works/sec"])
            hdd_perf = float(dev_val["hdd"]["works/sec"])
            print("%s %s %s %s %s %s" %
                  (fs,
                   ssd_perf/mem_perf, hdd_perf/mem_perf,
                   mem_perf, ssd_perf, hdd_perf),
                  file=self.out)
            # XXX: ugly ]]]
        print("\n", file=self.out)

    def gen_cmpdev(self, ncore, out_dir):
        self.out_dir  = out_dir
        subprocess.call("mkdir -p %s" % self.out_dir, shell=True)
        self.out_file = os.path.join(self.out_dir, ("cmpdev.%s.dat" % ncore))
        self.out = open(self.out_file, "w")
        ## TC
        # fs ssd-rel hdd-rel mem ssd hdd
        for bench in self.config["bench"]:
            self._gen_cmpdev_for_bench(ncore, bench)
        self.out.close()

def __print_usage():
    print("Usage: plotter.py --log [log file] ")
    print("                  --gp [gnuplot output]")
    print("                  --ty [sc | util]")
    print("                  --ncore [# core (only for util)]")

if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("--log",   help="Log file")
    parser.add_option("--ty",    help="{sc | util | cmpdev }")
    parser.add_option("--out",   help="output directory")
    parser.add_option("--ncore", help="# core (only for utilization and cmpdev)", default="1")
    (opts, args) = parser.parse_args()

    # check arg
    for opt in vars(opts):
        val = getattr(opts, opt)
        if val == None:
            print("Missing options: %s" % opt)
            parser.print_help()
            exit(1)
    # run
    plotter = Plotter(opts.log)
    if opts.ty == "sc":
        plotter.plot_sc(opts.out)
    elif opts.ty == "util":
        plotter.plot_util(int(opts.ncore), opts.out)
    elif opts.ty == "cmpdev":
        plotter.gen_cmpdev(int(opts.ncore), opts.out)
    else:
        __print_usage()
        exit(1)
