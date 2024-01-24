// SPDX-License-Identifier: MIT
/**
 * Microbenchmark
 *   FC. PROCESS = {create/delete files in 4KB at /test}
 *       - TEST: inode alloc/dealloc, block alloc/dealloc,
 *	        dentry insert/delete, block map insert/delete
 */
#define __USE_LARGEFILE64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdlib.h>
#include "fxmark.h"
#include "util.h"
#include "rdtsc.h"

static void set_test_file(struct worker *worker,
                          char *test_file)
{
    struct fx_opt *fx_opt = fx_opt_worker(worker);
    sprintf(test_file, "%s/u_file_tr-%d.dat",
            fx_opt->root, worker->id);
}

static int pre_work(struct worker *worker)
{
    struct bench *bench =  worker->bench;
    char path[PATH_MAX];
    int fd=-1, rc = 0;
    char *page = NULL;

    /* allocate data buffer aligned with pagesize*/                    
    if(posix_memalign((void **)&(worker->page), PAGE_SIZE, PAGE_SIZE)) 
      goto err_out;                                                    
    page = worker->page;                                               
    if (!page)                                                         
      goto err_out;                                                    

    /* time to create large file */
    set_test_file(worker, path);
    if ((fd = open(path, O_CREAT | O_RDWR | O_LARGEFILE, S_IRWXU)) == -1) {
      rc = errno;
      goto err_out;
    }

    /*set flag with O_DIRECT if necessary*/                   
    if(bench->directio && (fcntl(fd, F_SETFL, O_DIRECT)==-1)) 
      goto err_out;                                           

    for(;;++worker->private[0]) {
      rc = write(fd, page, PAGE_SIZE);
      if (rc != PAGE_SIZE) {
        if (errno == ENOSPC) {
          --worker->private[0];
          rc = 0;
          goto out;
        }
        goto err_out;
      }
    }
err_out:
    bench->stop = 1;
 out:
    /*put fd to worker's private*/
    worker->private[1] = (uint64_t)fd;
    free(page);
    worker->page=NULL;
    return rc;
}
#include <string.h>

static int main_work(struct worker *worker)
{
    struct bench *bench = worker->bench;
    uint64_t iter;
    int fd, rc = 0;
    char path[PATH_MAX];
    set_test_file(worker, path);

    /*get file */
    fd = (int)worker->private[1];

    for (iter = --worker->private[0]; iter > 0 && !bench->stop; --iter) {
      if (ftruncate(fd, iter * PAGE_SIZE) == -1) {
        rc = errno;
        goto err_out;
      }
    }
 out:
    close(fd);
    worker->works = (double)(worker->private[0] - iter);
    return rc;
 err_out:
    bench->stop = 1;
    rc = errno;
    goto out;
}

struct bench_operations u_file_tr_ops = {
    .pre_work  = pre_work,
    .main_work = main_work,
};
