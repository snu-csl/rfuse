// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include "fxmark.h"

struct bench_desc {
	const char *name;
	const char *desc;
	struct bench_operations *ops;
};

static struct bench_desc bench_table[] = {
	{"MWCL",
	 "inode allocation: each process creates files at its private directory",
	 &n_inode_alloc_ops},
	{"DWAL",
	 "block allocation: each process appends pages to a private file",
	 &n_blk_alloc_ops},
	{"DWOL",
	 "block write: each process overwrite a pages to a private file",
	 &n_blk_wrt_ops},
	{"MWRM",
	 "directory insert: each process moves files from its private directory to a common direcotry",
	 &n_dir_ins_ops},
	{"DWSL",
	 "journal commit: each process fsync a private file",
	 &n_jnl_cmt_ops},
	{"DWOM",
	 "mtime update: each process updates a private page of the shared file",
	 &n_mtime_upt_ops},
	{"MWRL",
	 "rename a file: each process rename a file in its private directory",
	 &n_file_rename_ops},
	{"DRBL",
	 "file read: each process read a block of its private file",
	 &n_file_rd_ops},
	{"DRBL_bg",
	 "file read with a background writer",
	 &n_file_rd_ops},
	{"DRBM",
	 "shared file read: each process reads its private region of the shared file",
	 &n_shfile_rd_ops},
	{"DRBM_bg",
	 "shared file read with a background writer",
	 &n_shfile_rd_bg_ops},
	{"DRBH",
	 "shared blk read: each process reads the same page of the shared file",
	 &n_shblk_rd_ops},
	{"DRBH_bg",
	 "shared blk read with a background writer",
	 &n_shblk_rd_bg_ops},
	{"MRDL",
	 "directory read: each process reads entries of its private directory",
	 &n_dir_rd_ops},
	{"MRDL_bg",
	 "directory read with a background writer",
	 &n_dir_rd_bg_ops},
	{"MRDM",
	 "shared directory read: each process reads entries of the shared directory",
	 &n_shdir_rd_ops},
	{"MRDM_bg",
	 "shared directory read with a background writer",
	 &n_shdir_rd_bg_ops},
	{"MRPL",
	 "path resolution for a private file",
	 &n_priv_path_rsl_ops},
	{"MRPM",
	 "path resolution: each process does stat() at random files in 8-level directories with 8-branching-out factor",
	 &n_path_rsl_ops},
	{"MRPM_bg",
	 "path resolution  with a background writer",
	 &n_path_rsl_bg_ops},
	{"MRPH",
	 "path resolution at the same level directory",
	 &n_spath_rsl_ops},
	{"MWCM",
	 "each process creates files in their private directory",
	 &u_file_cr_ops},
	{"MWUL",
	 "each process deletes files in their private directory",
	 &u_file_rm_ops},
	{"MWUM",
	 "each process deletes files at the test root directory",
	 &u_sh_file_rm_ops},
	{"DWTL",
	 "each process truncates its private file at the test root directory",
	 &u_file_tr_ops},
	{NULL, NULL, NULL},
};

static struct bench_operations *find_ops(char *type)
{
	struct bench_desc *bd = bench_table; 

	for (; bd->name != NULL; ++bd) {
		if (!strcmp(type, bd->name))
			return bd->ops;
	}
	return NULL;
}

static int parse_option(int argc, char *argv[], struct cmd_opt *opt)
{
	static struct option options[] = {
		{"type",      required_argument, 0, 't'}, 
		{"ncore",     required_argument, 0, 'n'}, 
		{"nbg",       required_argument, 0, 'g'}, 
		{"duration",  required_argument, 0, 'd'}, 
		{"directio",  required_argument, 0, 'D'}, 
		{"root",      required_argument, 0, 'r'}, 
		{"profbegin", required_argument, 0, 'b'},
		{"profend",   required_argument, 0, 'e'},
		{"proflog",   required_argument, 0, 'l'},
		{0,           0,                 0, 0},
	};
	int arg_cnt;

	opt->profile_start_cmd = "";
	opt->profile_stop_cmd  = "";
	opt->profile_stat_file = "";
	for(arg_cnt = 0; 1; ++arg_cnt) {
		int c, idx = 0;
		c = getopt_long(argc, argv, 
				"t:n:g:d:D:r:b:e:l:", options, &idx);
		if (c == -1)
			break; 
		switch(c) {
		case 't':
			opt->ops = find_ops(optarg);
			if (!opt->ops)
				return -EINVAL;
			break;
		case 'n':
			opt->ncore = atoi(optarg);
			break;
		case 'g':
			opt->nbg = atoi(optarg);
			break;
		case 'd':
			opt->duration = atoi(optarg);
			break;
		case 'D':
			opt->directio = atoi(optarg);
#if 0	/*optional debug*/
			if(opt->directio)
				fprintf(stderr, "DirectIO Enabled\n");
#endif
			break;
		case 'r':
			opt->root = optarg;
			break;
		case 'b':
			opt->profile_start_cmd = optarg;
			break;
		case 'e':
			opt->profile_stop_cmd = optarg;
			break;
		case 'l':
			opt->profile_stat_file = optarg;
			break;
		default:
			return -EINVAL;
		}
	}
	return arg_cnt;
}

static void usage(FILE *out)
{
	extern const char *__progname;
	struct bench_desc *bd = bench_table; 

	fprintf(out, "Usage: %s\n", __progname);
	fprintf(out, "  --type     = benchmark type\n");
	for (; bd->name != NULL; ++bd)
		fprintf(out, "    %s: %s\n", bd->name, bd->desc);
	fprintf(out, "  --ncore     = number of core\n");
	fprintf(out, "  --nbg       = number of background worker\n");
	fprintf(out, "  --duration  = duration in seconds\n");
	fprintf(out, "  --directio  = file flag set O_DIRECT : 0-false, 1-true\n"
		"                                         (only valid for DWxx type)\n");
	fprintf(out, "  --root      = test root directory\n");
	fprintf(out, "  --profbegin = profiling start command\n");
	fprintf(out, "  --profend   = profiling stop command\n");
	fprintf(out, "  --proflog   = profiling log file\n");
}

static void init_bench(struct bench *bench, struct cmd_opt *opt)
{
	struct fx_opt *fx_opt = fx_opt_bench(bench);

	bench->duration = opt->duration;
	bench->directio = opt->directio;
	strncpy(bench->profile_start_cmd,
		opt->profile_start_cmd, BENCH_PROFILE_CMD_BYTES);
	strncpy(bench->profile_stop_cmd,
		opt->profile_stop_cmd, BENCH_PROFILE_CMD_BYTES);
	strncpy(bench->profile_stat_file,
		opt->profile_stat_file, PATH_MAX);
	strncpy(fx_opt->root, opt->root, PATH_MAX);
	bench->ops = *opt->ops;
}

int main(int argc, char *argv[])
{
	struct cmd_opt opt = {NULL, 0, 0, 0, 0, NULL};
	struct bench *bench; 

	/* parse command line options */
	if (parse_option(argc, argv, &opt) < 4) {
		usage(stderr);
		exit(1);
	}

	/* create, initialize, and run a bench */ 
	bench = alloc_bench(opt.ncore, opt.nbg);
	init_bench(bench, &opt);
	run_bench(bench);
	report_bench(bench, stdout);

	return 0;
}
