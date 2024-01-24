// SPDX-License-Identifier: MIT
#pragma GCC diagnostic ignored "-Wcomment"
/**
 * Nanobenchmark: ADD
 *   DI. PROCESS = {move files from /test/$PROCESS/* to /test}
 *       - TEST: dir. insert
 */	      
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "fxmark.h"
#include "util.h"

static int stop_pre_work;

static void set_test_root(struct worker *worker, char *test_root)
{
	struct fx_opt *fx_opt = fx_opt_worker(worker);
	sprintf(test_root, "%s/%d", fx_opt->root, worker->id);
}

static void set_test_file(struct worker *worker, 
			  uint64_t file_id, char *test_file)
{
	struct fx_opt *fx_opt = fx_opt_worker(worker);
	sprintf(test_file, "%s/%d/n_dir_ins-%d-%" PRIu64 ".dat",
		fx_opt->root, worker->id, worker->id, file_id);
}

static void set_renamed_test_file(struct worker *worker, 
				  uint64_t file_id, char *test_file)
{
	struct fx_opt *fx_opt = fx_opt_worker(worker);
	sprintf(test_file, "%s/n_dir_ins-%d-%" PRIu64 ".dat",
		fx_opt->root, worker->id, file_id);
}

static void sighandler(int x)
{
	stop_pre_work = 1;
}

static int pre_work(struct worker *worker)
{
	struct bench *bench = worker->bench;
	char path[PATH_MAX];
	int fd, rm_cnt, i, rc = 0;

	/* perform pre_work for bench->duration */
	if (signal(SIGALRM, sighandler) == SIG_ERR) {
		rc = errno;
		goto err_out;
	}
	alarm(bench->duration);

	/* create private directory */
	set_test_root(worker, path);
	rc = mkdir_p(path);
	if (rc) goto err_out;

	/* create files at the private directory */
	for (; !stop_pre_work; ++worker->private[0]) {
		set_test_file(worker, worker->private[0], path);
		if ((fd = open(path, O_CREAT | O_RDWR, S_IRWXU)) == -1) {
			if (errno == ENOSPC)
				goto end_create;
			goto err_out;
		}
		close(fd);
	}
end_create:

	/* remove 5% of files to avoid ENOSPC error while move files */
	rm_cnt = ((double)worker->private[0] * 0.05) + 1;
	for (i = 0; worker->private[0] > 0 && i < rm_cnt; ++i) {
		--worker->private[0];
		set_test_file(worker, worker->private[0], path);
		rc = unlink(path);
		if (rc) goto err_out;
	}
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

	for (iter = 0; iter < worker->private[0] && !bench->stop; ++iter) {
		set_test_file(worker, iter, old_path);
		set_renamed_test_file(worker, iter, new_path);
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

struct bench_operations n_dir_ins_ops = {
	.pre_work  = pre_work, 
	.main_work = main_work,
};
