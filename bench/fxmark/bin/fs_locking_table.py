#!/usr/bin/env python3
import sys
import subprocess
import collections

class BuildFSLockingTable(object):

  def buildInitialTable(self):
    for lock in self.locks:
      lock_cell = collections.OrderedDict()
      for single_fs in self.fs:
        fs_cell_content = {
          "header":0,
          "source":0
          }
        lock_cell[single_fs] = fs_cell_content

      self.tableData[lock] = lock_cell

  def __init__(self, linux_src_dir):
    self.linux_dir = linux_src_dir
    self.locks = ["spinlock", "rwlock", "rwsem", "atomic", "mutex", "seqlock", "semaphore", "rcu", "sleepy-waiting"]
    self.fs = ["VFS", "btrfs", "ext4", "jbd2", "f2fs", "tmpfs", "xfs"]
    self.fsToMacro = {
        "VFS":"\\vfs",
        "btrfs":"\\btrfs",
        "ext4":"\\ext",
        "jbd2":"\\jbd2",
        "f2fs":"\\ffs",
        "tmpfs":"\\tmpfs",
        "xfs":"\\xfs"
        }

    self.FS_TO_HEADERS = {
        "VFS":[{
            "dir":"fs/*.h",
            "files":[
              "internal.h",
              "mount.h",
              "pnode.h"
              ]
          },
          {
            "dir":"include/linux/*.h",
            "files":[
              "fs.h",
              "dcache.h",
              "namei.h",
              "quotaops.h",
              "quota.h",
              "xattrr.h",
              "file.h",
              "fs.h",
              "writeback.h"
            ]
          }],
        "tmpfs":[{
            "dir":"include/linux/*.h",
            "files":[
              "shmem_fs.h",
            ]
          }],
        "jbd2":[{
            "dir":"fs/jbd2/*.h",
            "files":[
              "*.h",
              ]
          },
          {
            "dir":"include/linux/*h",
            "files":[
              "jbd2.h"
              ]
          }],
        "ext4":[{
            "dir":"fs/ext4/*.h",
            "files":[
              "*.h"
              ]
          }],
        "btrfs":[{
              "dir":"fs/btrfs/*.h",
              "files":[
                "*.h"
                ]
            }],
        "xfs":[{
          "dir":"fs/xfs/*.h",
          "files":[
            "*.h"
            ]
          }],
        "f2fs":[{
          "dir":"fs/f2fs/*.h",
          "files":[
            "*.h"
            ]
          }]
        }

    self.FS_TO_SOURCES = {
        "VFS":[{
            "dir":"fs/*.c",
            "files":[
              "*.c"
              ]
          }],
        "tmpfs":[{
            "dir":"mm/*.c",
            "files":[
              "shmem.c",
            ]
          }],
        "jbd2":[{
            "dir":"fs/jbd2/*.c",
            "files":[
              "*.c",
              ]
          }],
        "ext4":[{
            "dir":"fs/ext4/*.c",
            "files":[
              "*.c"
              ]
          }],
        "btrfs":[{
              "dir":"fs/btrfs/*.c",
              "files":[
                "*.c"
                ]
            }],
        "xfs":[{
          "dir":"fs/xfs/*.c",
          "files":[
            "*.c"
            ]
          }],
        "f2fs":[{
          "dir":"fs/f2fs/*.c",
          "files":[
            "*.c"
            ]
          }]
        }

    self.source_lock_types={
        "spinlock":"spin_lock\|spin_lock_irqsave\|spin_lock_irq\|spin_lock_bh",
        "rwlock":"read_lock\|read_lock_irqsave\|read_lock_irq\|read_lock_bh",
        "rwsem":"down_read",
        "atomic":"atomic_read\|atomic_set\|atomic_add\|atomic_sub\|atomic_inc\|atomic_dec\|atomic_sub_and_test\|atomic_dec_and_test\|atomic_inc_and_test\|atomic_add_negative\|atomic_add_return\|atomic_sub_return\|atomic_cmpxchg\|atomic_inc_return\|atomic_dec_return\|atomic_xchg\|atomic_inc_short\|atomic_clear_mask\|atomic_set_mask",
        "mutex":"mutex_lock\|mutex_lock_nested\|mutex_lock_killable_nested\|mutex_lock_interruptible_nested\|mutex_lock_interruptible\|mutex_lock_killable",
        "seqlock": "write_seqlock",
        "semaphore": "down",
        "rcu": "rcu_read_lock\|synchronize_rcu\|call_rcu",
        "sleepy-waiting":"wait_event\|xlog_grant_head_wait\|wait_on_bit_lock\|wait_on_bit_lock\|wait_on_page_bit"
        }

    self.header_lock_types={
        "spinlock":"spinlock_t",
        "rwlock":"rwlock_t",
        "rwsem":"rw_semaphore",
        "atomic":"atomic_t",
        "mutex":"mutex",
        "seqlock":"seqlock_t",
        "semaphore":"semaphore",
        "rcu":None,
        "sleepy-waiting":None
        }

    self.tableData = collections.OrderedDict()
    self.buildInitialTable()

  def exec_cmd(self, cmd, out=None):
    p = subprocess.Popen(cmd, shell=True, stdout=out, stderr=out)
    p.wait()
    return p

  def countSources(self, fs, lock_type):
    lock = self.source_lock_types[lock_type]
    sources = self.FS_TO_SOURCES[fs]
    headers = self.FS_TO_HEADERS[fs]
    count = 0
    for source_dir in sources:
      #print ('%s, %s'%(fs, lock_type))
      cmd = 'grep -I '
      for include in source_dir["files"]:
        cmd += '--include "%s" '%(include)
      cmd += '"%s" '%(lock)
      cmd += '%s/%s'%(self.linux_dir, source_dir["dir"])
      cmd += " | wc"
      p = self.exec_cmd(cmd, subprocess.PIPE)
      count += int(p.stdout.readlines()[0].decode("utf-8").strip().split(" ")[0].strip())
      #print(count)
      #print(cmd)
    # Do the same for the headers as we want to catch inlined functions as well:
    for header_dir in headers:
      cmd = 'grep -I '
      for include in header_dir["files"]:
        cmd += '--include "%s" '%(include)
      cmd += '"%s" '%(lock)
      cmd += '%s/%s'%(self.linux_dir, header_dir["dir"])
      cmd += " | wc"
      p = self.exec_cmd(cmd, subprocess.PIPE)
      count += int(p.stdout.readlines()[0].decode("utf-8").strip().split(" ")[0].strip())
    self.tableData[lock_type][fs]["source"] = count

  def countHeaders(self, fs, lock_type):
    lock = self.header_lock_types[lock_type]
    headers = self.FS_TO_HEADERS[fs]
    count = 0
    for header_dir in headers:
      #print ('%s, %s'%(fs, lock_type))
      cmd = 'grep -I '
      for include in header_dir["files"]:
        cmd += '--include "%s" '%(include)
      cmd += '"%s" '%(lock)
      cmd += '%s/%s'%(self.linux_dir, header_dir["dir"])
      cmd += " | wc"
      p = self.exec_cmd(cmd, subprocess.PIPE)
      count += int(p.stdout.readlines()[0].decode("utf-8").strip().split(" ")[0].strip())
      #print(count)
      #print(cmd)
    self.tableData[lock_type][fs]["header"] = count

  def countAllSources(self):
    for fs in self.FS_TO_SOURCES:
      for lock in self.source_lock_types:
        self.countSources(fs, lock)

  def countAllHeaders(self):
    for fs in self.FS_TO_HEADERS:
      for lock in self.header_lock_types:
        self.countHeaders(fs, lock)

  def printTable(self):
    self.countAllSources()
    self.countAllHeaders()
    #print(self.tableData)
    line_end = "\\\\\n"
    latex_table = " "
    total_per_fs = {}
    for single_fs in self.fs:
      latex_table += "& \multicolumn{2}{c}{\\textbf{%s}} " %(self.fsToMacro[single_fs])
      total_per_fs[single_fs] = {"header":0, "source":0}
    latex_table += line_end
    latex_table += " "
    for single_fs in self.fs:
      latex_table += "& Def & Use "
    latex_table += line_end
    latex_table += "\\toprule\n"
    for lock in self.tableData:
      #latex_table += "\midrule\n"
      latex_table += "\\cc{%s} " % (lock)
      for single_fs in self.fs:
        if self.header_lock_types[lock] is not None:
          count = self.tableData[lock][single_fs]["header"]
          latex_table += "& %s " % count
          total_per_fs[single_fs]["header"] += count
        else:
          latex_table += "& - "
        count = self.tableData[lock][single_fs]["source"]
        latex_table += "& %s " % count
        total_per_fs[single_fs]["source"] += count
      latex_table += line_end
    latex_table += "\\toprule\n"
    latex_table += "Total "
    for single_fs in self.fs:
      latex_table += "& %s & %s " % (total_per_fs[single_fs]["header"], total_per_fs[single_fs]["source"])
    latex_table += line_end
    latex_table += "\\toprule\n"
    print(latex_table)


if __name__ == "__main__":
  lt = BuildFSLockingTable(sys.argv[1])
  lt.printTable()
