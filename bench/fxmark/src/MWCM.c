// SPDX-License-Identifier: MIT
/**
 * Microbenchmark
 *   FC. PROCESS = {create/delete files in 4KB at /test}
 *       - TEST: inode alloc/dealloc, block alloc/dealloc, 
 *	        dentry insert/delete, block map insert/delete
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

static int pre_work(struct worker *worker)
{
	struct fx_opt *fx_opt = fx_opt_worker(worker);
	return mkdir_p(fx_opt->root);
}

static int main_work(struct worker *worker)
{
	static char page[PAGE_SIZE];
	struct bench *bench = worker->bench;
	struct fx_opt *fx_opt = fx_opt_bench(bench);
	uint64_t iter;
	int rc = 0;

	for (iter = 0; !bench->stop; ++iter) {
		char file[PATH_MAX];
		int fd;
		/* create, write, and close */
		snprintf(file, PATH_MAX, "%s/m_file_cr-%d-%" PRIu64 ".dat", 
			 fx_opt->root, worker->id, iter);
		if ((fd = open(file, O_CREAT | O_RDWR, S_IRWXU)) == -1)
			goto err_out;
	        if (write(fd, page, sizeof(page)) == -1)
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

struct bench_operations u_file_cr_ops = {
	.pre_work  = pre_work, 
	.main_work = main_work,
};
