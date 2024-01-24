// SPDX-License-Identifier: MIT
/**
 * Nanobenchmark: ADD
 *   IA. PROCESS = {create empty files at /test/$PROCESS}
 *      - TEST: inode alloc
 */	      
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "fxmark.h"
#include "util.h"

static void set_test_root(struct worker *worker, char *test_root)
{
	struct fx_opt *fx_opt = fx_opt_worker(worker);
	sprintf(test_root, "%s/%d", fx_opt->root, worker->id);
}

static int pre_work(struct worker *worker)
{
	char test_root[PATH_MAX];
	set_test_root(worker, test_root);
	return mkdir_p(test_root);
}

static int main_work(struct worker *worker)
{
	char test_root[PATH_MAX];
	struct bench *bench = worker->bench;
	uint64_t iter;
	int rc = 0;

	set_test_root(worker, test_root);
	for (iter = 0; !bench->stop; ++iter) {
		char file[PATH_MAX];
		int fd;
		/* create and close */
		snprintf(file, PATH_MAX, "%s/n_inode_alloc-%" PRIu64 ".dat", 
			 test_root, iter);
		if ((fd = open(file, O_CREAT | O_RDWR, S_IRWXU)) == -1)
			goto err_out;
		close(fd);
	}
out:
	worker->works = (double)iter;
	return rc;
err_out:
	bench->stop = 1;
	rc = errno;
	goto out;
}

struct bench_operations n_inode_alloc_ops = {
	.pre_work  = pre_work, 
	.main_work = main_work,
};
