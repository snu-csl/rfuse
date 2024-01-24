// SPDX-License-Identifier: MIT
#pragma GCC diagnostic ignored "-Wcomment"
/**
 * Nanobenchmark: META
 *   RN. PROCESS = {rename a file name in a private directory}
 *       - TEST: concurrent update of dentry cache
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

static void set_test_file(struct worker *worker, 
			  uint64_t file_id, char *test_file)
{
	struct fx_opt *fx_opt = fx_opt_worker(worker);
	sprintf(test_file, "%s/%d/n_file_rename-%" PRIu64 ".dat",
		fx_opt->root, worker->id, file_id);
}

static int pre_work(struct worker *worker)
{
	char path[PATH_MAX];
	int fd, rc = 0;

	/* create private directory */
	set_test_root(worker, path);
	rc = mkdir_p(path);
	if (rc) goto err_out;

	/* create files at the private directory */
	set_test_file(worker, worker->private[0], path);
	if ((fd = open(path, O_CREAT | O_RDWR, S_IRWXU)) == -1)
		goto err_out;
	fsync(fd);
	close(fd);
out:
	return rc;
err_out:
	rc = errno;
	goto out;
}

static int main_work(struct worker *worker)
{
	struct bench *bench = worker->bench;
	char old_path[PATH_MAX], new_path[PATH_MAX];
	uint64_t iter;
	int rc = 0;

	for (iter = 0; !bench->stop; ++iter) {
		set_test_file(worker,   worker->private[0], old_path);
		set_test_file(worker, ++worker->private[0], new_path);
		rc = rename(old_path, new_path);
		if (rc) goto err_out;
	}
out:
	bench->stop = 1;
	worker->works = (double)iter;
	return rc;
err_out:
	rc = errno;
	goto out;
}

struct bench_operations n_file_rename_ops = {
	.pre_work  = pre_work, 
	.main_work = main_work,
};
