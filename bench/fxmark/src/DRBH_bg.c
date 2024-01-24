// SPDX-License-Identifier: MIT
/**
 * Nanobenchmark: Read operation with a backgroud inhibitor
 *   RSF. PROCESS = {read the same page of /test/test.file}
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
	char path[PATH_MAX];
	char page[PAGE_SIZE];
	int fd, rc;

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

	if (write(fd, page, sizeof(page)) == -1)
		goto err_out;
	
	fsync(fd);
	close(fd);
out:
	return rc;
err_out:
	rc = errno;
	goto out;
}

static int fg_work(struct worker *worker)
{
	struct bench *bench = worker->bench;
	char path[PATH_MAX];
	char page[PAGE_SIZE];
	int fd, rc = 0;
	uint64_t iter = 0;

	set_test_file(worker, path);
	if ((fd = open(path, O_CREAT | O_RDWR, S_IRWXU)) == -1)
		goto err_out;
	
	for (iter = 0; !bench->stop; ++iter) {
	        if (pread(fd, page, sizeof(page), 0) == -1)
			goto err_out;
	}
	close(fd);
out:
	worker->works = (double)iter;
	return rc;
err_out:
	bench->stop = 1;
	rc = errno;
	goto out;
}

static int bg_work(struct worker *worker)
{
	struct bench *bench = worker->bench;
	char path[PATH_MAX];
	char page[PAGE_SIZE];
	int fd, rc = 0;
	uint64_t iter = 0;

	set_test_file(worker, path);
	if ((fd = open(path, O_CREAT | O_RDWR, S_IRWXU)) == -1)
		goto err_out;
	
	for (iter = 0; !bench->stop; ++iter) {
	        if (pwrite(fd, page, sizeof(page), 0) == -1)
			goto err_out;
	}
	close(fd);
out:
	worker->works = (double)iter;
	return rc;
err_out:
	bench->stop = 1;
	rc = errno;
	goto out;
}

static int main_work(struct worker *worker)
{
	if (worker->is_bg)
		return bg_work(worker);
	return fg_work(worker);
}

struct bench_operations n_shblk_rd_bg_ops = {
	.pre_work  = pre_work, 
	.main_work = main_work,
};
