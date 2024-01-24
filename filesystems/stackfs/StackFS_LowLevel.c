/*
 * Copyright (c) 2018      Manu Mathew
 * Copyright (c) 2016-2017 Bharath Kumar Reddy Vangoor
 * Copyright (c) 2017      Swaminathan Sivaraman
 * Copyright (c) 2016-2018 Vasily Tarasov
 * Copyright (c) 2016-2018 Erez Zadok
 * Copyright (c) 2016-2018 Stony Brook University
 * Copyright (c) 2016-2018 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define FUSE_USE_VERSION 31
#define _XOPEN_SOURCE 500
#define _GNU_SOURCE
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <fuse.h>
#include <fuse_lowlevel.h>
#include <rfuse.h>
#include <assert.h>
#include <stddef.h>
#include <fcntl.h> /* Definition of AT_* constants */
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/xattr.h>
#include <sys/syscall.h>

FILE *logfile;
#define TESTING_XATTR 0
#define USE_SPLICE 0

#define TRACE_FILE "/trace_stackfs.log1"
#define TRACE_FILE_LEN 18
pthread_spinlock_t spinlock; /* Protecting the above spin lock */
char banner[4096];

void print_usage(void)
{
	printf("USAGE	: ./StackFS_ll -r <rootDir>|-rootdir=<rootDir> ");
	printf("[--attrval=<time(secs)>] [--statsdir=<statsDirPath>] ");
	printf("<mountDir> [FUSE options]\n"); /* For checkPatch.pl */
	printf("<rootDir>  : Root Directory containg the Low Level F/S\n");
	printf("<attrval>  : Time in secs to let kernel know how muh time ");
	printf("the attributes are valid\n"); /* For checkPatch.pl */
	printf("<statsDirPath> : Path for copying any statistics details\n");
	printf("<mountDir> : Mount Directory on to which the F/S should be ");
	printf("mounted\n"); /* For checkPatch.pl */
	printf("Example    : ./StackFS_ll -r rootDir/ mountDir/\n");
}

int log_open(char *statsDir)
{
	char *trace_path = NULL;

	if (statsDir) {
		trace_path = (char *)malloc(strlen(statsDir) +
				TRACE_FILE_LEN + 1);
		memset(trace_path, 0, strlen(statsDir) + TRACE_FILE_LEN + 1);
		strncpy(trace_path, statsDir, strlen(statsDir));
		strncat(trace_path, TRACE_FILE, TRACE_FILE_LEN);
	} else {
		trace_path = (char *)malloc(TRACE_FILE_LEN);
		memset(trace_path, 0, TRACE_FILE_LEN);
		strncpy(trace_path, TRACE_FILE + 1, TRACE_FILE_LEN-1);
	}
	printf("Trace file location : %s\n", trace_path);
	logfile = fopen(trace_path, "w");
	if (logfile == NULL) {
		perror("logfile");
		free(trace_path);
		return -1;
	}
	free(trace_path);
	setvbuf(logfile, NULL, _IOLBF, 0);
	return 0;
}

void log_close(void)
{

	if (logfile)
		fclose(logfile);
}


int64_t print_timer(void)
{
	struct timespec tms;

	if (clock_gettime(CLOCK_REALTIME, &tms)) {
		printf("ERROR\n");
		return 0;
	}
	int64_t micros = tms.tv_sec * 1000000;

	micros += tms.tv_nsec/1000;
	if (tms.tv_nsec % 1000 >= 500)
		++micros;
	return micros;
}

/* called with file lock */
int print_banner(void)
{
	int len;
	int64_t time;
	int pid;
	unsigned long tid;

	banner[0] = '\0';
	time = print_timer();
	pid = getpid();
	tid = syscall(SYS_gettid);
	if (time == 0)
		return -1;
	len = sprintf(banner, "Time : %"PRId64" Pid : %d Tid : %lu ",
			time, pid, tid);
	(void) len;
	fputs(banner, logfile);
	return 0;
}

void StackFS_trace(const char *format, ...)
{
	va_list ap;
	int ret = 0;

	/*lock*/
	pthread_spin_lock(&spinlock);
	if (logfile) {
		/*Banner : time + pid + tid*/
		ret = print_banner();
		if (ret)
			goto trace_out;
		/*Done with banner*/
		va_start(ap, format);
		vfprintf(logfile, format, ap);
		/*Done with trace*/
		fprintf(logfile, "\n");
	}
trace_out:
	/*unlock*/
	pthread_spin_unlock(&spinlock);
}

/*=============Hash Table implementation==========================*/

/* The node structure that we maintain as our local cache which maps
 * the ino numbers to their full path, this address is stored as part
 * of the value of the hash table */
struct lo_inode {
	struct lo_inode *next;
	struct lo_inode *prev;
	/* Full path of the underlying ext4 path
	 * correspoding to its ino (easy way to extract back) */
	char *name;
	/* Inode numbers and dev no's of
	 * underlying EXT4 F/s for the above path */
	ino_t ino;
	dev_t dev;
	/* inode number sent to lower F/S */
	ino_t lo_ino;
	/* Lookup count of this node */
	uint64_t nlookup;
};

#define HASH_TABLE_MIN_SIZE 8192

/* The structure is used for maintaining the hash table
 * 1. array	--> Buckets to store the key and values
 * 2. use	--> Current size of the hash table
 * 3. size	--> Max size of the hash table
 * (we start with NODE_TABLE_MIN_SIZE)
 * 4. split	--> used to resize the table
 * (this is how fuse-lib does) */
struct node_table {
	struct lo_inode **array;
	size_t use;
	size_t size;
	size_t split;
};

static int hash_table_init(struct node_table *t)
{
	t->size = HASH_TABLE_MIN_SIZE;
	t->array = (struct lo_inode **) calloc(1,
			sizeof(struct lo_inode *) * t->size);
	if (t->array == NULL) {
		fprintf(stderr, "fuse: memory allocation failed\n");
		return -1;
	}
	t->use = 0;
	t->split = 0;

	return 0;
}

void hash_table_destroy(struct node_table *t)
{
	free(t->array);
}

static int hash_table_resize(struct node_table *t)
{
	size_t newsize = t->size * 2;
	void *newarray = NULL;

	newarray = realloc(t->array, sizeof(struct lo_inode *) * newsize);
	if (newarray == NULL) {
		fprintf(stderr, "fuse: memory allocation failed\n");
		return -1;
	}

	t->array = newarray;
	/* zero the newly allocated space */
	memset(t->array + t->size, 0, t->size * sizeof(struct lo_inode *));
	t->size = newsize;
	t->split = 0;

	return 0;
}

/* The structure which is used to store the hash table
 * and it is always comes as part of the req structure */
struct lo_data {
	/* hash table mapping key (inode no + complete path) -->
	 *  value (linked list of node's - open chaining) */
	struct node_table hash_table;
	/* protecting the above hash table */
	pthread_spinlock_t spinlock;
	/* put the root Inode '/' here itself for faster
	 * access and some other useful raesons */
	struct lo_inode root;
	/* do we still need this ? let's see*/
	double attr_valid;
};

struct lo_dirptr {
	DIR *dp;
	struct dirent *entry;
	off_t offset;
};

static struct lo_dirptr *lo_dirptr(struct fuse_file_info *fi)
{
	return ((struct lo_dirptr *) ((uintptr_t) fi->fh));
}

static struct lo_data *get_lo_data(fuse_req_t req)
{
	return (struct lo_data *) fuse_req_userdata(req);
}

static struct lo_inode *lo_inode(fuse_req_t req, fuse_ino_t ino)
{
	if (ino == FUSE_ROOT_ID)
		return &get_lo_data(req)->root;
	else
		return (struct lo_inode *) (uintptr_t) ino;
}

static char *lo_name(fuse_req_t req, fuse_ino_t ino)
{
	return lo_inode(req, ino)->name;
}

/* This is what given to the kernel FUSE F/S */
static ino_t get_lower_fuse_inode_no(fuse_req_t req, fuse_ino_t ino) {
	return lo_inode(req, ino)->lo_ino;
}


static double lo_attr_valid_time(fuse_req_t req)
{
	return ((struct lo_data *) fuse_req_userdata(req))->attr_valid;
}

static void construct_full_path(fuse_req_t req, fuse_ino_t ino,
		char *fpath, const char *path)
{
	strcpy(fpath, lo_name(req, ino));
	strncat(fpath, "/1", 1);
	strncat(fpath, path, PATH_MAX);
}

/* Function which generates the hash depending on the ino number
 * and full path */
static size_t name_hash(struct lo_data *lo_data, fuse_ino_t ino,
		const char *fullpath)
{
	uint64_t hash = ino;
	uint64_t oldhash;
	const char *name;

	name = fullpath;

	for (; *name; name++)
		hash = hash * 31 + (unsigned char) *name;

	hash %= lo_data->hash_table.size;
	oldhash = hash % (lo_data->hash_table.size / 2);
	if (oldhash >= lo_data->hash_table.split)
		return oldhash;
	else
		return hash;
}

static void remap_hash_table(struct lo_data *lo_data)
{
	struct node_table *t = &lo_data->hash_table;
	struct lo_inode **nodep;
	struct lo_inode **next;
	struct lo_inode *prev;
	size_t hash;

	if (t->split == t->size / 2)
		return;

	/* split this bucket by recalculating the hash */
	hash = t->split;
	t->split++;

	for (nodep = &t->array[hash]; *nodep != NULL; nodep = next) {
		struct lo_inode *node = *nodep;
		size_t newhash = name_hash(lo_data, node->ino, node->name);

		if (newhash != hash) {
			prev = node->prev;
			*nodep = node->next;
			if (*nodep)
				(*nodep)->prev = prev;

			node->prev = NULL;
			node->next = t->array[newhash];
			if (t->array[newhash])
				(t->array[newhash])->prev = node;
			t->array[newhash] = node;
			next = nodep;
		} else {
			next = &node->next;
		}
	}

	/* If we have reached the splitting to half of the size
	 * then double the size of hash table */
	if (t->split == t->size / 2)
		hash_table_resize(t);
}

static int insert_to_hash_table(struct lo_data *lo_data,
		struct lo_inode *lo_inode)
{
	size_t hash = name_hash(lo_data, lo_inode->ino, lo_inode->name);

	lo_inode->next = lo_data->hash_table.array[hash];
	if (lo_data->hash_table.array[hash])
		(lo_data->hash_table.array[hash])->prev = lo_inode;
	lo_data->hash_table.array[hash] = lo_inode;
	lo_data->hash_table.use++;

	if (lo_data->hash_table.use >= lo_data->hash_table.size / 2)
		remap_hash_table(lo_data);

	return 0;
}

static void hash_table_reduce(struct node_table *t)
{
	size_t newsize = t->size / 2;
	void *newarray;

	if (newsize < HASH_TABLE_MIN_SIZE)
		return;

	newarray = realloc(t->array, sizeof(struct node *) * newsize);
	if (newarray != NULL)
		t->array = newarray;

	t->size = newsize;
	t->split = t->size / 2;
}

static void remerge_hash_table(struct lo_data *lo_data)
{
	struct node_table *t = &lo_data->hash_table;
	int iter;

	/* This means all the hashes would be under the half size
	 * of table (so simply make it half) */
	if (t->split == 0)
		hash_table_reduce(t);

	for (iter = 8; t->split > 0 && iter; iter--) {
		struct lo_inode **upper;

		t->split--;
		upper = &t->array[t->split + t->size / 2];
		if (*upper) {
			struct lo_inode **nodep;
			struct lo_inode *prev = NULL;

			for (nodep = &t->array[t->split];
					*nodep; nodep = &(*nodep)->next)
				prev = *nodep;

			*nodep = *upper;
			(*upper)->prev = prev;
			*upper = NULL;
			break;
		}
	}
}

static int delete_from_hash_table(struct lo_data *lo_data,
		struct lo_inode *lo_inode)
{
	struct lo_inode *prev, *next;

	prev = next = NULL;
	size_t hash = 0;

	pthread_spin_lock(&lo_data->spinlock);

	prev = lo_inode->prev;
	next = lo_inode->next;

	if (prev) {
		prev->next = next;
		if (next)
			next->prev = prev;
		goto del_out;
	} else {
		hash = name_hash(lo_data, lo_inode->ino, lo_inode->name);

		if (next)
			next->prev = NULL;

		lo_data->hash_table.array[hash] = next;
	}

del_out:
	/* free the lo_inode  */
	lo_inode->prev = lo_inode->next = NULL;
	free(lo_inode->name);
	free(lo_inode);

	lo_data->hash_table.use--;
	if (lo_data->hash_table.use < lo_data->hash_table.size / 4)
		remerge_hash_table(lo_data);

	pthread_spin_unlock(&lo_data->spinlock);
	return 0;
}

/* Function which checks the inode in the hash table
 * by calculating the hash from ino and full path */
static struct lo_inode *lookup_lo_inode(struct lo_data *lo_data,
		struct stat *st, const char *fullpath)
{
	size_t hash = name_hash(lo_data, st->st_ino, fullpath);
	struct lo_inode *node;

	for (node = lo_data->hash_table.array[hash]; node != NULL;
			node = node->next) {
		if ((node->ino == st->st_ino) && (node->dev == st->st_dev) &&
				(strcmp(node->name, fullpath) == 0))
			return node;
	}

	return NULL;
}

void free_hash_table(struct lo_data *lo_data)
{
	struct lo_inode *node, *next;
	int i;

	for (i = 0; i < lo_data->hash_table.size; i++) {
		node = lo_data->hash_table.array[i];
		while (node) {
			next = node->next;
			/* free up the node */
			free(node->name);
			free(node);
			node = next;
		}
	}
}

/* A function which checks the hash table and returns the lo_inode
 * otherwise a new lo_inode is created and inserted into the hashtable
 * req		--> for the hash_table reference
 * st		--> to check against the ino and dev_id
 *			when navigating the bucket chain
 * fullpath	--> full path is used to construct the key */
struct lo_inode *find_lo_inode(fuse_req_t req, struct stat *st, char *fullpath)
{
	struct lo_data *lo_data;
	struct lo_inode *lo_inode;
	int res;

	lo_data = get_lo_data(req);

	pthread_spin_lock(&lo_data->spinlock);

	lo_inode = lookup_lo_inode(lo_data, st, fullpath);

	if (lo_inode == NULL) {
		/* create the node and insert into hash_table */
		lo_inode =  calloc(1, sizeof(struct lo_inode));
		if (!lo_inode)
			goto find_out;
		lo_inode->ino = st->st_ino;
		lo_inode->dev = st->st_dev;
		lo_inode->name = strdup(fullpath);
		/* store this for mapping (debugging) */
		lo_inode->lo_ino = (uintptr_t) lo_inode;
		lo_inode->next = lo_inode->prev = NULL;

		/* insert into hash table */
		res = insert_to_hash_table(lo_data, lo_inode);
		if (res == -1) {
			free(lo_inode->name);
			free(lo_inode);
			lo_inode = NULL;
			goto find_out;
		}
	}
	lo_inode->nlookup++;
find_out:
	pthread_spin_unlock(&lo_data->spinlock);
	return lo_inode;
}

static void stackfs_ll_lookup(fuse_req_t req, fuse_ino_t parent,
		const char *name)
{
	struct fuse_entry_param e;
	int res;
	char *fullPath = NULL;
	double attr_val;

	fullPath = (char *)malloc(PATH_MAX);
	construct_full_path(req, parent, fullPath, name);
	
	attr_val = lo_attr_valid_time(req);
	memset(&e, 0, sizeof(e));

	e.attr_timeout = attr_val;
	e.entry_timeout = attr_val; /* dentry timeout */
	
	res = lstat(fullPath, &e.attr);

	if (res == 0) {
		struct lo_inode *inode;

		inode = find_lo_inode(req, &e.attr, fullPath);

		if (fullPath)
			free(fullPath);

		if (!inode)
			fuse_reply_err(req, ENOMEM);
		else {
			e.ino = inode->lo_ino;
			fuse_reply_entry(req, &e);
		}
	} else {
		if (fullPath)
			free(fullPath);
		fuse_reply_err(req, ENOENT);
	}
}

static void stackfs_ll_getattr(fuse_req_t req, fuse_ino_t ino,
		struct fuse_file_info *fi)
{
	int res;
	struct stat buf;
	(void) fi;
	double attr_val;

	attr_val = lo_attr_valid_time(req);
	res = lstat(lo_name(req, ino), &buf);

	if (res == -1) {
		printf("getattr failed: %s\n", lo_name(req, ino));
		return (void) fuse_reply_err(req, errno);
	}

	fuse_reply_attr(req,&buf,attr_val);
}

static void stackfs_ll_setattr(fuse_req_t req, fuse_ino_t ino,
		struct stat *attr, int to_set, struct fuse_file_info *fi)
{
	int res;
	(void) fi;
	struct stat buf;
	double attr_val;

	attr_val = lo_attr_valid_time(req);
	// generate_start_time(req);
	if (to_set & FUSE_SET_ATTR_SIZE) {
		/*Truncate*/
		res = truncate(lo_name(req, ino), attr->st_size);
		if (res != 0) {
			// generate_end_time(req);
			// populate_time(req);
			return (void) fuse_reply_err(req, errno);
		}
	}

	if (to_set & (FUSE_SET_ATTR_ATIME | FUSE_SET_ATTR_MTIME)) {
		/* Update Time */
		struct utimbuf tv;

		tv.actime = attr->st_atime;
		tv.modtime = attr->st_mtime;
		res = utime(lo_name(req, ino), &tv);
		if (res != 0) {
			// generate_end_time(req);
			// populate_time(req);
			return (void) fuse_reply_err(req, errno);
		}
	}

	if(to_set & FUSE_SET_ATTR_MODE) {
		mode_t mode;
		
		mode = attr->st_mode;
		res = chmod(lo_name(req, ino), mode);
		if (res != 0) {
			// generate_end_time(req);
			// populate_time(req);
			return (void) fuse_reply_err(req, errno);
		}
	}

	if(to_set & (FUSE_SET_ATTR_UID | FUSE_SET_ATTR_GID)) {	
		uid_t uid = (to_set & FUSE_SET_ATTR_UID) ?
			attr->st_uid : (uid_t) -1;
		gid_t gid = (to_set & FUSE_SET_ATTR_GID) ?
			attr->st_gid : (gid_t) -1;

		res = chown(lo_name(req, ino), uid, gid);
		if (res != 0) {
			// generate_end_time(req);
			// populate_time(req);
			return (void) fuse_reply_err(req, errno);
		}
	}
	memset(&buf, 0, sizeof(buf));
	res = stat(lo_name(req, ino), &buf);
	// generate_end_time(req);
	// populate_time(req);
	if (res != 0)
		return (void) fuse_reply_err(req, errno);

	fuse_reply_attr(req, &buf, attr_val);
}

static void stackfs_ll_create(fuse_req_t req, fuse_ino_t parent,
		const char *name, mode_t mode, struct fuse_file_info *fi)
{
	int fd, res;
	struct fuse_entry_param e;
	char *fullPath = NULL;
	double attr_val;

	// struct timespec start, end;
	// long long unsigned tt;

	//StackFS_trace("Create called on %s and parent ino : %llu",
	//				name, lo_inode(req, parent)->ino);

	fullPath = (char *)malloc(PATH_MAX);
	construct_full_path(req, parent, fullPath, name);
	attr_val = lo_attr_valid_time(req);

	//struct timespec start,end;
	//clock_gettime(CLOCK_MONOTONIC, &start);
	fd = creat(fullPath, mode);
	//clock_gettime(CLOCK_MONOTONIC, &end);
	//printf("CREATE TIME: %lu\n", (end.tv_sec * 1000000000 + end.tv_nsec) - (start.tv_sec * 1000000000 + start.tv_nsec));	
	if (fd == -1) {
		if (fullPath)
			free(fullPath);
		return (void)fuse_reply_err(req, errno);
	}

	memset(&e, 0, sizeof(e));

	e.attr_timeout = attr_val;
	e.entry_timeout = attr_val;

	res = stat(fullPath, &e.attr);
	// generate_end_time(req);
	// populate_time(req);

	if (res == 0) {
		/* insert lo_inode into the hash table */
		struct lo_data *lo_data;
		struct lo_inode *lo_inode;

		lo_inode = calloc(1, sizeof(struct lo_inode));
		if (!lo_inode) {
			if (fullPath)
				free(fullPath);

			return (void) fuse_reply_err(req, errno);
		}

		lo_inode->ino = e.attr.st_ino;
		lo_inode->dev = e.attr.st_dev;
		lo_inode->name = strdup(fullPath);
		/* store this for mapping (debugging) */
		lo_inode->lo_ino = (uintptr_t) lo_inode;
		lo_inode->next = lo_inode->prev = NULL;
		free(fullPath);

		lo_data = get_lo_data(req);
		pthread_spin_lock(&lo_data->spinlock);

		res = insert_to_hash_table(lo_data, lo_inode);

		pthread_spin_unlock(&lo_data->spinlock);

		if (res == -1) {
			free(lo_inode->name);
			free(lo_inode);
			fuse_reply_err(req, EBUSY);
		} else {
			lo_inode->nlookup++;
			e.ino = lo_inode->lo_ino;
			//StackFS_trace("Create called, e.ino : %llu", e.ino);
			fi->fh = fd;
			fuse_reply_create(req, &e, fi);
		}
	} else {
		if (fullPath)
			free(fullPath);
		fuse_reply_err(req, errno);
	}
}


static void stackfs_ll_mkdir(fuse_req_t req, fuse_ino_t parent,
		const char *name, mode_t mode)
{
	int res;
	struct fuse_entry_param e;
	char *fullPath = NULL;
	double attr_val;

	fullPath = (char *)malloc(PATH_MAX);
	construct_full_path(req, parent, fullPath, name);
	attr_val = lo_attr_valid_time(req);

	// generate_start_time(req);
	res = mkdir(fullPath, mode);


	if (res == -1) {
		/* Error occurred while creating the directory */
		if (fullPath)
			free(fullPath);

		// generate_end_time(req);
		// populate_time(req);

		return (void)fuse_reply_err(req, errno);
	}

	/* Assign the stats of the newly created directory */
	memset(&e, 0, sizeof(e));
	e.attr_timeout = attr_val;
	e.entry_timeout = attr_val; /* may be attr_val */
	res = stat(fullPath, &e.attr);
	// generate_end_time(req);
	// populate_time(req);

	if (res == 0) {
		/* insert lo_inode into the hash table */
		struct lo_data *lo_data;
		struct lo_inode *lo_inode;

		lo_inode = calloc(1, sizeof(struct lo_inode));
		if (!lo_inode) {
			if (fullPath)
				free(fullPath);

			return (void) fuse_reply_err(req, errno);
		}

		lo_inode->ino = e.attr.st_ino;
		lo_inode->dev = e.attr.st_dev;
		lo_inode->name = strdup(fullPath);
		/* store this for mapping (debugging) */
		lo_inode->lo_ino = (uintptr_t) lo_inode;
		lo_inode->next = lo_inode->prev = NULL;
		free(fullPath);

		lo_data = get_lo_data(req);

		pthread_spin_lock(&lo_data->spinlock);

		res = insert_to_hash_table(lo_data, lo_inode);

		pthread_spin_unlock(&lo_data->spinlock);

		if (res == -1) {
			free(lo_inode->name);
			free(lo_inode);
			fuse_reply_err(req, EBUSY);
		} else {
			lo_inode->nlookup++;
			e.ino = lo_inode->lo_ino;
			//printf("Making directory finished\n");
			fuse_reply_entry(req, &e);
		}
	} else {
		if (fullPath)
			free(fullPath);
		fuse_reply_err(req, errno);
	}
}



static void stackfs_ll_open(fuse_req_t req, fuse_ino_t ino,
		struct fuse_file_info *fi)
{
	int fd;
	fd = open(lo_name(req, ino), fi->flags);
	
	if (fd == -1)
		return (void) fuse_reply_err(req, errno);

	fi->fh = fd;

	fuse_reply_open(req, fi);
}



static void stackfs_ll_opendir(fuse_req_t req, fuse_ino_t ino,
		struct fuse_file_info *fi)
{
	DIR *dp;
	struct lo_dirptr *d;

	
	dp = opendir(lo_name(req, ino));

	if (dp == NULL)
		return (void) fuse_reply_err(req, errno);

	d = malloc(sizeof(struct lo_dirptr));
	d->dp = dp;
	d->offset = 0;
	d->entry = NULL;

	fi->fh = (uintptr_t) d;

	fuse_reply_open(req, fi);
}




static void stackfs_ll_read(fuse_req_t req, fuse_ino_t ino, size_t size,
		off_t offset, struct fuse_file_info *fi)
{
	int res;
	(void) ino;

	StackFS_trace("StackFS Read start on inode : %llu", get_lower_fuse_inode_no(req, ino));
	if (USE_SPLICE) {
		struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size);

		//StackFS_trace("Splice Read name : %s, off : %lu, size : %zu",
		//			lo_name(req, ino), offset, size);

		buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
		buf.buf[0].fd = fi->fh;
		buf.buf[0].pos = offset;
		fuse_reply_data(req, &buf, FUSE_BUF_SPLICE_MOVE);
	} else {
		char *buf;

		//StackFS_trace("Read on name : %s, Kernel inode : %llu, fuse inode : %llu, off : %lu, size : %zu",
		//			lo_name(req, ino), get_lower_fuse_inode_no(req, ino), get_higher_fuse_inode_no(req, ino), offset, size);
		buf = (char *)malloc(size);
		res = pread(fi->fh, buf, size, offset);
		if (res == -1)
			return (void) fuse_reply_err(req, errno);
		res = fuse_reply_buf(req, buf, res);
		free(buf);
	}
	StackFS_trace("StackFS Read end on inode : %llu", get_lower_fuse_inode_no(req, ino));
}



static void stackfs_ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
		off_t off, struct fuse_file_info *fi)
{
	struct lo_dirptr *d;
	char *buf = NULL;
	char *p = NULL;
	size_t rem;
	int err;
	(void) ino;

	//StackFS_trace("Readdir called on name : %s and inode : %llu",
	//			lo_name(req, ino), lo_inode(req, ino)->ino);
	d = lo_dirptr(fi);
	buf = malloc(size*sizeof(char));
	if (!buf)
		return (void) fuse_reply_err(req, ENOMEM);

	// generate_start_time(req);
	/* If offset is not same, need to seek it */
	if (off != d->offset) {
		seekdir(d->dp, off);
		d->entry = NULL;
		d->offset = off;
	}
	p = buf;
	rem = size;
	while (1) {
		size_t entsize;
		off_t nextoff;

		if (!d->entry) {
			errno = 0;
			d->entry = readdir(d->dp);
			if (!d->entry) {
				if (errno && rem == size) {
					err = errno;
					goto error;
				}
				break;
			}
		}
		nextoff = telldir(d->dp);

		struct stat st = {
			.st_ino = d->entry->d_ino,
			.st_mode = d->entry->d_type << 12,
		};
		entsize = fuse_add_direntry(req, p, rem,
				d->entry->d_name, &st, nextoff);
		/* The above function returns the size of the entry size even though
		 * the copy failed due to smaller buf size, so I'm checking after this
		 * function and breaking out incase we exceed the size.
		 */
		if (entsize > rem)
			break;

		p += entsize;
		rem -= entsize;

		d->entry = NULL;
		d->offset = nextoff;
	}

	// generate_end_time(req);
	// populate_time(req);
	fuse_reply_buf(req, buf, size - rem);
	free(buf);

	return;

error:
	// generate_end_time(req);
	// populate_time(req);
	free(buf);

	fuse_reply_err(req, err);
}


static void stackfs_ll_release(fuse_req_t req, fuse_ino_t ino,
		struct fuse_file_info *fi)
{
	(void) ino;

	close(fi->fh);

	fuse_reply_err(req, 0);
}


static void stackfs_ll_releasedir(fuse_req_t req, fuse_ino_t ino,
		struct fuse_file_info *fi)
{
	struct lo_dirptr *d;
	(void) ino;

	//StackFS_trace("Releasedir called on name : %s and inode : %llu",
	//			lo_name(req, ino), lo_inode(req, ino)->ino);
	d = lo_dirptr(fi);
	// generate_start_time(req);
	closedir(d->dp);
	// generate_end_time(req);
	// populate_time(req);
	free(d);
	fuse_reply_err(req, 0);
}


static void stackfs_ll_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
		size_t size, off_t off, struct fuse_file_info *fi)
{
	int res;
	(void) ino;
	
	res = pwrite(fi->fh, buf, size, off);

	if (res == -1)
		return (void) fuse_reply_err(req, errno);

	fuse_reply_write(req, res);
}

#if	USE_SPLICE
static void stackfs_ll_write_buf(fuse_req_t req, fuse_ino_t ino,
		struct fuse_bufvec *buf, off_t off, struct fuse_file_info *fi)
{
	int res;
	(void) ino;

	struct fuse_bufvec dst = FUSE_BUFVEC_INIT(fuse_buf_size(buf));

	//StackFS_trace("Splice Write_buf on name : %s, off : %lu, size : %zu",
	//			lo_name(req, ino), off, buf->buf[0].size);

	// generate_start_time(req);
	dst.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
	dst.buf[0].fd = fi->fh;
	dst.buf[0].pos = off;
	res = fuse_buf_copy(&dst, buf, FUSE_BUF_SPLICE_NONBLOCK);
	// generate_end_time(req);
	// populate_time(req);
	if (res >= 0)
		fuse_reply_write(req, res);
	else
		fuse_reply_err(req, res);
}
#endif


static void stackfs_ll_unlink(fuse_req_t req, fuse_ino_t parent,
		const char *name)
{
	int res;
	char *fullPath = NULL;

	//StackFS_trace("Unlink called on name : %s, parent inode : %llu",
	//				name, lo_inode(req, parent)->ino);
	fullPath = (char *)malloc(PATH_MAX);
	construct_full_path(req, parent, fullPath, name);
	// generate_start_time(req);
	res = unlink(fullPath);
	// generate_end_time(req);
	// populate_time(req);
	if (res == -1)
		fuse_reply_err(req, errno);
	else
		fuse_reply_err(req, res);

	if (fullPath)
		free(fullPath);
}



static void stackfs_ll_rmdir(fuse_req_t req, fuse_ino_t parent,
		const char *name)
{
	int res;
	char *fullPath = NULL;

	//StackFS_trace("rmdir called with name : %s, parent inode : %llu",
	//				name, lo_inode(req, parent)->ino);
	fullPath = (char *)malloc(PATH_MAX);
	construct_full_path(req, parent, fullPath, name);
	// generate_start_time(req);
	res = rmdir(fullPath);
	// generate_end_time(req);
	// populate_time(req);

	if (res == -1)
		fuse_reply_err(req, errno);
	else
		fuse_reply_err(req, res);

	if (fullPath)
		free(fullPath);
}


static void forget_inode(fuse_req_t req, struct lo_inode *inode,
		uint64_t nlookup)
{
	int res;

	assert(inode->nlookup >= nlookup);
	inode->nlookup -= nlookup;

	if (!inode->nlookup)
		res = delete_from_hash_table(get_lo_data(req), inode);

	(void) res;
}

static void stackfs_ll_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	struct lo_inode *inode = lo_inode(req, ino);

	forget_inode(req, inode, nlookup);
	fuse_reply_none(req);
}

static void stackfs_ll_flush(fuse_req_t req, fuse_ino_t ino,
		struct fuse_file_info *fi)
{
	int err;
	err = 0;
	fuse_reply_err(req, err);
}

static void stackfs_ll_statfs(fuse_req_t req, fuse_ino_t ino)
{
	int res;
	struct statvfs buf;

	if (ino) {
		memset(&buf, 0, sizeof(buf));
		res = statvfs(lo_name(req, ino), &buf);
	}

	if (!res)
		fuse_reply_statfs(req, &buf);
	else
		fuse_reply_err(req, res);
}


static void stackfs_ll_fsync(fuse_req_t req, fuse_ino_t ino, int datasync,
		struct fuse_file_info *fi)
{
	int res;


	if (datasync)
		res = fdatasync(fi->fh);
	else
		res = fsync(fi->fh);

	fuse_reply_err(req, res);
}

static void stackfs_ll_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
		      fuse_ino_t newparent, const char *newname,
		      unsigned int flags)
{
	struct fuse_entry_param e;
	int res, statres;
	char *oldPath = NULL;
	char *newPath = NULL;
	double attr_val;

	if (flags) {
		fuse_reply_err(req, EINVAL);
		return;
	}

	oldPath = (char*)malloc(PATH_MAX);
	newPath = (char*)malloc(PATH_MAX);
	
	construct_full_path(req, parent, oldPath, name);
	construct_full_path(req, newparent, newPath, newname);

	res = rename(oldPath, newPath);
	
	attr_val = lo_attr_valid_time(req);
	memset(&e, 0, sizeof(e));

	e.attr_timeout = attr_val;
	e.entry_timeout = attr_val; /* dentry timeout */

	statres = stat(newPath, &e.attr);

	if (statres == 0) {
		struct lo_inode *inode;

		inode = find_lo_inode(req, &e.attr, oldPath);

		if (!inode)
			fuse_reply_err(req, ENOMEM);
		else {
			free(inode->name);
			inode->name = strdup(newPath);
			// e.ino = inode->lo_ino;
			// fuse_reply_entry(req, &e);
		}
	} else {
		fuse_reply_err(req, ENOENT);
	}

	fuse_reply_err(req, res == -1 ? errno : 0);

	if(oldPath)
		free(oldPath);
	if(newPath)
		free(newPath);
}

static void stackfs_ll_symlink(fuse_req_t req, const char *link, fuse_ino_t parent, const char *name) 
{	
	struct fuse_entry_param e;
	char *fullPath;
	int res;
	double attr_val;

	fullPath = (char*)malloc(PATH_MAX);
	construct_full_path(req, parent, fullPath, name);
	attr_val = lo_attr_valid_time(req);
	
	res = symlink(link, fullPath);

	if (res) {
		if (fullPath)
			free(fullPath);
		return (void)fuse_reply_err(req, errno);
	}
	printf("link: %s, path(name) %s\n", link, fullPath);

	memset(&e, 0, sizeof(e));

	e.attr_timeout = attr_val;
	e.entry_timeout = attr_val;

	res = lstat(fullPath, &e.attr);
	
	printf("%X\n", e.attr.st_mode & 0xF000);
	if (res == 0) {
		/* insert lo_inode into the hash table */
		struct lo_data *lo_data;
		struct lo_inode *lo_inode;

		lo_inode = calloc(1, sizeof(struct lo_inode));
		if (!lo_inode) {
			if (fullPath)
				free(fullPath);

			return (void) fuse_reply_err(req, errno);
		}

		lo_inode->ino = e.attr.st_ino;
		lo_inode->dev = e.attr.st_dev;
		lo_inode->name = strdup(fullPath);
		/* store this for mapping (debugging) */
		lo_inode->lo_ino = (uintptr_t) lo_inode;
		lo_inode->next = lo_inode->prev = NULL;
		free(fullPath);

		lo_data = get_lo_data(req);
		pthread_spin_lock(&lo_data->spinlock);

		res = insert_to_hash_table(lo_data, lo_inode);

		pthread_spin_unlock(&lo_data->spinlock);

		if (res == -1) {
			free(lo_inode->name);
			free(lo_inode);
			fuse_reply_err(req, EBUSY);
		} else {
			lo_inode->nlookup++;
			e.ino = lo_inode->lo_ino;
			//StackFS_trace("Create called, e.ino : %llu", e.ino);
			fuse_reply_entry(req, &e);
		}
	} else {
		if (fullPath)
			free(fullPath);
		fuse_reply_err(req, errno);
	}

}

static void stackfs_ll_readlink(fuse_req_t req, fuse_ino_t ino)
{
	char buf[PATH_MAX+1];
	int res;
	
	res = readlink(lo_name(req, ino), buf, sizeof(buf));
	if(res == -1)
		return (void) fuse_reply_err(req, errno);
	
	if(res == sizeof(buf))
		return (void) fuse_reply_err(req, ENAMETOOLONG);

	buf[res] = '\0';

	fuse_reply_readlink(req, buf);
}

static void stackfs_ll_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent, const char *newname) 
{
	struct fuse_entry_param e;
	char *newfullPath;
	int res;
	double attr_val;

	newfullPath = (char*)malloc(PATH_MAX);
	construct_full_path(req, newparent, newfullPath, newname);
	attr_val = lo_attr_valid_time(req);
	
	res = link(lo_name(req, ino), newfullPath);

	if (res) {
		if (newfullPath)
			free(newfullPath);
		return (void)fuse_reply_err(req, errno);
	}

	memset(&e, 0, sizeof(e));

	e.attr_timeout = attr_val;
	e.entry_timeout = attr_val;

	res = lstat(newfullPath, &e.attr);
	
	if (res == 0) {
		/* insert lo_inode into the hash table */
		struct lo_data *lo_data;
		struct lo_inode *lo_inode;

		lo_inode = calloc(1, sizeof(struct lo_inode));
		if (!lo_inode) {
			if (newfullPath)
				free(newfullPath);

			return (void) fuse_reply_err(req, errno);
		}

		lo_inode->ino = e.attr.st_ino;
		lo_inode->dev = e.attr.st_dev;
		lo_inode->name = strdup(newfullPath);
		/* store this for mapping (debugging) */
		lo_inode->lo_ino = (uintptr_t) lo_inode;
		lo_inode->next = lo_inode->prev = NULL;
		free(newfullPath);

		lo_data = get_lo_data(req);
		pthread_spin_lock(&lo_data->spinlock);

		res = insert_to_hash_table(lo_data, lo_inode);

		pthread_spin_unlock(&lo_data->spinlock);

		if (res == -1) {
			free(lo_inode->name);
			free(lo_inode);
			fuse_reply_err(req, EBUSY);
		} else {
			lo_inode->nlookup++;
			e.ino = lo_inode->lo_ino;
			//StackFS_trace("Create called, e.ino : %llu", e.ino);
			fuse_reply_entry(req, &e);
		}
	} else {
		if (newfullPath)
			free(newfullPath);
		fuse_reply_err(req, errno);
	}

}
static struct fuse_lowlevel_ops hello_ll_oper = {
	.lookup		=	stackfs_ll_lookup,
	.getattr	=	stackfs_ll_getattr,	
	.statfs		=	stackfs_ll_statfs,	
	.setattr	=	stackfs_ll_setattr,	
	.flush		=	stackfs_ll_flush,	
	.fsync		=	stackfs_ll_fsync,	
	.forget		=	stackfs_ll_forget, 	
	.create		=	stackfs_ll_create, 	
	.open		=	stackfs_ll_open,	
	.read		=	stackfs_ll_read,	
	.write		=	stackfs_ll_write,	
#if	USE_SPLICE
	.write_buf	=	stackfs_ll_write_buf,
#endif
	.release	=	stackfs_ll_release, 
	.unlink		=	stackfs_ll_unlink, 
	.mkdir		=	stackfs_ll_mkdir,	
	.rmdir		=	stackfs_ll_rmdir,	
	.opendir	=	stackfs_ll_opendir,	
	.readdir	=	stackfs_ll_readdir,	
	.releasedir	=	stackfs_ll_releasedir, 
	.symlink	=	stackfs_ll_symlink,
	.link		=	stackfs_ll_link,
	.readlink	=	stackfs_ll_readlink,
	.rename 	= 	stackfs_ll_rename
};

struct stackFS_info {
	char	*rootDir;
	char	*statsDir;/* Path to copy any statistics details */
	double	attr_valid;/* Time in secs for attribute validation */
	int	is_help;
	int	tracing;
};

#define STACKFS_OPT(t, p) { t, offsetof(struct stackFS_info, p), 1 }

static const struct fuse_opt stackfs_opts[] = {
	STACKFS_OPT("-r %s", rootDir),
	STACKFS_OPT("--rootdir=%s", rootDir),
	STACKFS_OPT("--statsdir=%s", statsDir),
	STACKFS_OPT("--attrval=%lf", attr_valid),
	FUSE_OPT_KEY("--tracing", 1),
	FUSE_OPT_KEY("-h", 0),
	FUSE_OPT_KEY("--help", 0),
	FUSE_OPT_END
};

static int stackfs_process_arg(void *data, const char *arg,
		int key, struct fuse_args *outargs)
{
	struct stackFS_info *s_info = data;

	(void)outargs;
	(void)arg;

	switch (key) {
		case 0:
			s_info->is_help = 1;
			return 0;
		case 1:
			s_info->tracing	= 1;
			return 0;
		default:
			return 1;
	}
}

int main(int argc, char **argv)
{
	int res = 0, err = 0;
	char *rootDir = NULL;
	char *statsDir = NULL;
	char *resolved_statsDir = NULL;
	char *resolved_rootdir_path = NULL;
	int multithreaded;

	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	/*Default attr valid time is 1 sec*/
	struct stackFS_info s_info = {NULL, NULL, 1.0, 0, 0};

	res = fuse_opt_parse(&args, &s_info, stackfs_opts, stackfs_process_arg);

	if (res) {
		printf("Failed to parse arguments\n");
		return -1;
	}

	if (s_info.is_help) {
		print_usage();
		return 0;
	}

	if (!s_info.rootDir) {
		printf("Root Directory is mandatory\n");
		print_usage();
		return -1;
	}

	if (s_info.statsDir) {
		statsDir = s_info.statsDir;
		resolved_statsDir = realpath(statsDir, NULL);
		if (resolved_statsDir == NULL) {
			printf("There is a problem in resolving the stats ");
			printf("Directory passed %s\n", statsDir);
			perror("Error");
			res = -1;
			goto out1;
		}
	}

	rootDir = s_info.rootDir;
	struct lo_data *lo = NULL;

	if (rootDir) {
		lo = (struct lo_data *) calloc(1, sizeof(struct lo_data));
		if (!lo) {
			fprintf(stderr, "fuse: memory allocation failed\n");
			res = -1;
			goto out2; /* free the resolved_statsDir */
		}
		resolved_rootdir_path = realpath(rootDir, NULL);
		if (!resolved_rootdir_path) {
			printf("There is a problem in resolving the root ");
			printf("Directory Passed %s\n", rootDir);
			perror("Error");
			res = -1;
			goto out3; /* free both resolved_statsDir, lo */
		}
		if (res == 0) {
			(lo->root).name = resolved_rootdir_path;
			(lo->root).ino = FUSE_ROOT_ID;
			(lo->root).nlookup = 2;
			(lo->root).next = (lo->root).prev = NULL;
			lo->attr_valid = s_info.attr_valid;
			/* Initialise the hash table and assign */
			res = hash_table_init(&lo->hash_table);
			if (res == -1)
				goto out4;
			/* Initialise the spin lock for table */
			pthread_spin_init(&(lo->spinlock), 0);
		}
	} else {
		res = -1;
		goto out2;
	}

	struct fuse_cmdline_opts opts;
	// struct fuse_chan *ch;
	// char *mountpoint;

	// res = fuse_parse_cmdline(&args, &mountpoint, &multithreaded, NULL);
	res = fuse_parse_cmdline(&args, &opts);
	if(res != 0)
		goto out4;	

	opts.singlethread = 0;
	multithreaded = 1;

	/* Initialise the spinlock before the logfile creation */
	pthread_spin_init(&spinlock, 0);
	if (s_info.tracing) {
		err = log_open(resolved_statsDir);
		if (err)
			printf("No log file created(but not a fatle error, ");
		printf("so proceeding)\n");
	} else
		printf("No tracing\n");

	printf("Multi Threaded : %d\n", multithreaded);

	struct fuse_session *se;
	if (res != -1) {
		fuse_lowlevel_version();
		se = fuse_session_new(&args, &hello_ll_oper, sizeof(hello_ll_oper),lo);
		fuse_set_signal_handlers(se);
		fuse_session_mount(se, opts.mountpoint);
		printf("Mounted Successfully\n");

		if (multithreaded)
			err = fuse_session_loop_mt_31(se,opts.clone_fd);
		else
			err = fuse_session_loop(se);
		
		fuse_session_unmount(se);
		StackFS_trace("Function Trace : Session Unmount");
		fuse_remove_signal_handlers(se);
		fuse_session_destroy(se);
		StackFS_trace("Function Trace : Session Destroy");
	}
	/* free the arguments */
	fuse_opt_free_args(&args);
	/* destroy the lock protecting the hash table */
	pthread_spin_destroy(&(lo->spinlock));
	/* free up the hash table */
	free_hash_table(lo);
	/* destroy the hash table */
	hash_table_destroy(&lo->hash_table);

	/* destroy the lock protecting the log file */
	pthread_spin_destroy(&spinlock);

	/* close the log file (if any) */
	log_close();
out4:
	if (resolved_rootdir_path)
		free(resolved_rootdir_path);
out3:
	if (lo)
		free(lo);
out2:
	if (resolved_statsDir)
		free(resolved_statsDir);
out1:
	return res;
}
