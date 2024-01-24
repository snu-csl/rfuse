// SPDX-License-Identifier: MIT
/**
 * Nanobenchmark: Path resolution
 *	 PR. PROCESS = {fstat in pre-constructed path}
 *		 - TEST: concurrent access of dentry & inode cache
 */		  
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "fxmark.h"
#include "util.h"

static void set_test_file(struct worker *worker, char *test_file)
{
	struct fx_opt *fx_opt = fx_opt_worker(worker);
	sprintf(test_file, "%s/%d/0/0/0/0", fx_opt->root, worker->id);
}

static int pre_work(struct worker *worker)
{
	int fd;
	char path[PATH_MAX];

	set_test_file(worker, path);
	/* discard last / */
	path[strlen(path)-2] = '\0';
	mkdir_p(path);

	set_test_file(worker, path);
	if ((fd = open(path, O_CREAT | O_RDWR, S_IRWXU)) == -1)
		goto err_out;
	close(fd);
	
	return 0;
	
err_out:
	return errno;
}

static int main_work(struct worker *worker)
{
	struct bench *bench = worker->bench;
	char path[PATH_MAX];
	struct stat sb;
	int rc = 0;
	uint64_t iter = 0;

	set_test_file(worker, path);
	
	for (iter = 0; !bench->stop; ++iter) {
		if (stat(path, &sb) == -1)
			goto err_out;
	}
out:
	worker->works = (double)iter;
	return rc;
err_out:
	bench->stop = 1;
	rc = errno;
	goto out;
}

struct bench_operations n_priv_path_rsl_ops = {
	.pre_work  = pre_work, 
	.main_work = main_work,
};
