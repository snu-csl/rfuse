// SPDX-License-Identifier: MIT
/**
 * Nanobenchmark: Path resolution with a background writer
 *   PR. PROCESS = {fstat in pre-constructed path}
 *       - TEST: concurrent access of dentry & inode cache
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

#define PATH_DEPTH 5
#define BRANCHING_OUT_FACTOR 8
#define BG_WRITER_BASE 1000
static const unsigned int mods[PATH_DEPTH] = {BRANCHING_OUT_FACTOR,
					      BRANCHING_OUT_FACTOR, 
					      BRANCHING_OUT_FACTOR,
					      BRANCHING_OUT_FACTOR,
					      BRANCHING_OUT_FACTOR};

static void set_digits(unsigned int len, 
		       unsigned int *digits, const unsigned int *mods, 
		       char sep, char *buf)
{
	unsigned int i; 
	for (i = 0; i < len; ++i)
		buf += sprintf(buf, "%c%d", sep, digits[i] % mods[i]);
}

static void set_bg_digits(unsigned int len, 
			  unsigned int *digits, const unsigned int *mods, 
			  char sep, char *buf)
{
	unsigned int i; 
	for (i = 0; i < len; ++i) {
		unsigned int base = (i == (len - 1)) ? BG_WRITER_BASE : 0;
		buf += sprintf(buf, "%c%d", sep, base + (digits[i] % mods[i]));
	}
}

static void set_test_path(struct worker *worker, 
			  unsigned int len,
			  unsigned int *digits, const unsigned int *mods,
			  char *path)
{
	struct fx_opt *fx_opt = fx_opt_worker(worker);
	path += sprintf(path, "%s", fx_opt->root);
	set_digits(len, digits, mods, '/', path);
}

static void set_bg_test_path(struct worker *worker, 
			  unsigned int len,
			  unsigned int *digits, const unsigned int *mods,
			  char *path)
{
	struct fx_opt *fx_opt = fx_opt_worker(worker);
	path += sprintf(path, "%s", fx_opt->root);
	set_bg_digits(len, digits, mods, '/', path);
}

static void randomize_digits(unsigned int len, unsigned int *digits)
{
	int i;

	digits[0] = pseudo_random(digits[0]);
	for (i = 1; i < len; ++i) {
		digits[i] = pseudo_random(digits[i-1]);
	}
}

static int pre_work(struct worker *worker)
{
	char path[PATH_MAX];
	unsigned int i, j, k, l, m; 
	int rc;

	/* a leader takes over all pre_work() */
	if (worker->id != 0)
		return 0;

	/* create test files */
	for (i = 0; i < BRANCHING_OUT_FACTOR; ++i) {
		for (j = 0; j < BRANCHING_OUT_FACTOR; ++j) {
			for (k = 0; k < BRANCHING_OUT_FACTOR; ++k) {
				for (l = 0; l < BRANCHING_OUT_FACTOR; ++l) {
					unsigned int test_dir[] = {i, j, k, l};
					set_test_path(worker, 4, test_dir, mods, path);
					rc = mkdir_p(path);
					if (rc) goto err_out;

					for (m = 0; m < BRANCHING_OUT_FACTOR; ++m) {
						unsigned int test_file[] = {i, j, k, l, m};
						int fd;
						set_test_path(worker, 5, test_file, mods, path);
						if ((fd = open(path, 
							       O_CREAT | O_RDWR, 
							       S_IRWXU)) == -1)
							goto err_out;
						close(fd);
					}
				}
			}
		}
	}
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
	unsigned int digits[PATH_DEPTH] = {worker->id, };
	struct stat sb;
	int rc = 0;
	uint64_t iter = 0;

	for (iter = 0; !bench->stop; ++iter) {
		randomize_digits(PATH_DEPTH, digits);
		set_test_path(worker, PATH_DEPTH, digits, mods, path);

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

static int bg_work(struct worker *worker)
{
	struct bench *bench = worker->bench;
	char path[PATH_MAX];
	unsigned int digits[PATH_DEPTH] = {worker->id, };
	struct stat sb;
	unsigned int seed = worker->id, test_depth;
	int rc = 0;
	uint64_t iter = 0;

	for (iter = 0; !bench->stop; ++iter) {
		/* randomly decide path depth for testing */ 
		seed = pseudo_random(seed);
		test_depth = 1 + (seed % PATH_DEPTH);

		/* generate a random depth */ 
		randomize_digits(test_depth, digits);
		set_bg_test_path(worker, test_depth, digits, mods, path);

		/* if there is such file, delete it. otherwise, create it. */
		if (stat(path, &sb) == -1) {
			int fd;
			if ((fd = open(path, O_CREAT | O_RDWR, S_IRWXU)) == -1)
				goto err_out;
			close(fd);
		}
		else {
			if (unlink(path) == -1)
				goto err_out;
		}
	}
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

struct bench_operations n_path_rsl_bg_ops = {
	.pre_work  = pre_work, 
	.main_work = main_work,
};
