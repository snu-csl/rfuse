// SPDX-License-Identifier: MIT
/**
 * Nanobenchmark: Read operation
 *   RSF. PROCESS = {read the same page of /test/test.file}
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <stdlib.h>
#include <assert.h>
#include "fxmark.h"
#include "util.h"

static void set_shared_test_root(struct worker *worker, char *test_root)
{
        struct fx_opt *fx_opt = fx_opt_worker(worker);
        sprintf(test_root, "%s", fx_opt->root);
}

static void set_test_file(struct worker *worker, char *test_root)
{
        struct fx_opt *fx_opt = fx_opt_worker(worker);
        sprintf(test_root, "%s/n_shblk_rd.dat", fx_opt->root);
}

static int pre_work(struct worker *worker)
{
        struct bench *bench = worker->bench;
        char path[PATH_MAX];
        char *page=NULL;
        int fd=-1, rc=-1;

        /*Allocate aligned buffer*/
        if(posix_memalign((void **)&(worker->page), PAGE_SIZE, PAGE_SIZE))
                goto err_out;
        page = worker->page;
        if (!page)
                goto err_out;

        /* a leader takes over all pre_work() */
        if (worker->id != 0)
                return 0;

        /* create a test file */
        set_shared_test_root(worker, path);
        rc = mkdir_p(path);
        if (rc) return rc;

        set_test_file(worker, path);
        if ((fd = open(path, O_CREAT | O_RDWR, S_IRWXU)) == -1)
                goto err_out;

        /*set flag with O_DIRECT if necessary*/
        if(bench->directio && (fcntl(fd, F_SETFL, O_DIRECT)==-1))
                goto err_out;

        if (write(fd, page, PAGE_SIZE) != PAGE_SIZE)
                goto err_out;

        fsync(fd);
        close(fd);
out:
        return rc;
err_out:
        rc = errno;
        if(page)
                free(page);
        goto out;
}

static int main_work(struct worker *worker)
{
        struct bench *bench = worker->bench;
        char path[PATH_MAX];
        char *page=worker->page;
        int fd, rc = 0;
        uint64_t iter = 0;

        assert(page);

        set_test_file(worker, path);
        if ((fd = open(path, O_CREAT | O_RDWR, S_IRWXU)) == -1)
                goto err_out;

        /*set flag with O_DIRECT if necessary*/
        if(bench->directio && (fcntl(fd, F_SETFL, O_DIRECT)==-1))
                goto err_out;

        for (iter = 0; !bench->stop; ++iter) {
                if (pread(fd, page, PAGE_SIZE, 0) != PAGE_SIZE)
                        goto err_out;
        }
        close(fd);
out:
        worker->works = (double)iter;
        return rc;
err_out:
        bench->stop = 1;
        rc = errno;
        free(page);
        goto out;
}

struct bench_operations n_shblk_rd_ops = {
        .pre_work  = pre_work,
        .main_work = main_work,
};
