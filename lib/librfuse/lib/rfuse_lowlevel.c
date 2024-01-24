#define _GNU_SOURCE

#include "config.h"
#include "fuse_i.h"
#include "fuse_kernel.h"
#include "fuse_opt.h"
#include "fuse_misc.h"
#include "mount_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#ifdef DEBUG
	static struct timespec temp_time;
	static long timestamps[14] = {0, }; 

	#define GET_TIMESTAMPS(i)  clock_gettime(CLOCK_REALTIME, &temp_time); \
				   timestamps[i] = temp_time.tv_sec * 1000000000 + temp_time.tv_nsec;
#else
	#define GET_TIMESTAMPS(i) ;
#endif

#define RFUSE_SPLICE_READ_NO_DATA 0x1000
// ******************************* Ring buffer operations ******************************* //

struct rfuse_address_entry *rfuse_read_pending_head(struct rfuse_iqueue *riq){
	struct ring_buffer_1 *pending = &riq->pending;
	unsigned int head = pending->head;
	unsigned int tail = rfuse_smp_load_acquire(&pending->tail);
	struct rfuse_address_entry *ret = NULL;
	if(head < tail){
		// printf("pending head: %u\n",head & pending->mask);
		ret = &pending->uaddr[head & pending->mask];
	}
	return ret;
}

void rfuse_extract_pending_head(struct rfuse_iqueue *riq){
	struct ring_buffer_1 *pending = &riq->pending;
	unsigned int next = pending->head + 1;
	rfuse_smp_store_release(&pending->head,next);
}

struct rfuse_forget_entry *rfuse_read_forgets_head(struct rfuse_iqueue *riq){
	struct ring_buffer_3 *forgets = &riq->forgets;
	unsigned int head = forgets->head;
	unsigned int tail = rfuse_smp_load_acquire(&forgets->tail);
	struct rfuse_forget_entry *ret = NULL;
	if(head < tail)
		ret = &forgets->uaddr[head & forgets->mask];
	return ret;
}

void rfuse_extract_forgets_head(struct rfuse_iqueue *riq){
	struct ring_buffer_3 *forgets = &riq->forgets;
	unsigned int next = forgets->head + 1;
	rfuse_smp_store_release(&forgets->head,next);
}

struct rfuse_address_entry *rfuse_read_completes_tail(struct rfuse_iqueue *riq){
	struct ring_buffer_1 *completes = &riq->completes;
	struct rfuse_address_entry *ret = NULL;
	unsigned int head;
	unsigned int next;

	head = rfuse_smp_load_acquire(&completes->head);
	next = completes->tail + 1;

	if(next - head <=  completes->entries){
		ret = &completes->uaddr[completes->tail & completes->mask];
	}
	return ret;
}

void rfuse_submit_completes_tail(struct rfuse_iqueue *riq){
	struct ring_buffer_1 *completes = &riq->completes;
	unsigned int next = completes->tail + 1;
	rfuse_smp_store_release(&completes->tail,next);
}

// ******************************* ULR operations ******************************* //


void rfuse_list_init_req(struct rfuse_user_req *req){
	req->next = req;
	req->prev = req;
}

void rfuse_list_del_req(struct rfuse_user_req *req)
{
	struct rfuse_user_req *prev = req->prev;
	struct rfuse_user_req *next = req->next;
	prev->next = next;
	next->prev = prev;
}

static void rfuse_list_add_req(struct rfuse_user_req *req, struct rfuse_user_req *next)
{
	struct rfuse_user_req *prev = next->prev;
	req->next = next;
	req->prev = prev;
	prev->next = req;
	next->prev = req;
}

struct rfuse_user_req *rfuse_ll_alloc_req(struct fuse_session *se, int riq_id)
{
	struct rfuse_user_req *req;

	req = (struct rfuse_user_req *)calloc(1, sizeof(struct rfuse_user_req));
	if (req == NULL) {
		fuse_log(FUSE_LOG_ERR, "rfuse: failed to allocate user level request\n");
	} else {
		req->se = se;
		req->ctr = 1;
		req->riq_id = riq_id;
		req->riq = se->riq[riq_id];
		rfuse_list_init_req(req);
		pthread_mutex_init(&req->lock, NULL);
	}

	return req;
}

static void rfuse_destroy_req(fuse_req_t req)
{
	pthread_mutex_destroy(&req->lock);
	free(req);
}


void rfuse_free_req(fuse_req_t req)
{
	int ctr;
	struct fuse_session *se = req->se;

	req->u.ni.func = NULL;
	req->u.ni.data = NULL;
	pthread_mutex_lock(&se->riq_lock[req->riq_id]);
	rfuse_list_del_req(req);
	pthread_mutex_unlock(&se->riq_lock[req->riq_id]);
	ctr = --req->ctr;
	fuse_chan_put(req->ch);
	req->ch = NULL;
	if (!ctr)
		rfuse_destroy_req(req);
}



// ******************************* Original Functions ******************************* //

static unsigned long rfuse_calc_timeout_sec(double t)
{
	if (t > (double) ULONG_MAX)
		return ULONG_MAX;
	else if (t < 0.0)
		return 0;
	else
		return (unsigned long) t;
}

static unsigned int rfuse_calc_timeout_nsec(double t)
{
	double f = t - (double) rfuse_calc_timeout_sec(t);
	if (f < 0.0)
		return 0;
	else if (f >= 0.999999999)
		return 999999999;
	else
		return (unsigned int) (f * 1.0e9);
}

static void rfuse_convert_stat(const struct stat *stbuf, struct fuse_attr *attr)
{
	attr->ino	= stbuf->st_ino;
	attr->mode	= stbuf->st_mode;
	attr->nlink	= stbuf->st_nlink;
	attr->uid	= stbuf->st_uid;
	attr->gid	= stbuf->st_gid;
	attr->rdev	= stbuf->st_rdev;
	attr->size	= stbuf->st_size;
	attr->blksize	= stbuf->st_blksize;
	attr->blocks	= stbuf->st_blocks;
	attr->atime	= stbuf->st_atime;
	attr->mtime	= stbuf->st_mtime;
	attr->ctime	= stbuf->st_ctime;
	attr->atimensec = ST_ATIM_NSEC(stbuf);
	attr->mtimensec = ST_MTIM_NSEC(stbuf);
	attr->ctimensec = ST_CTIM_NSEC(stbuf);
}

static void rfuse_convert_attr(const struct fuse_setattr_in *attr, struct stat *stbuf)
{
	stbuf->st_mode	       = attr->mode;
	stbuf->st_uid	       = attr->uid;
	stbuf->st_gid	       = attr->gid;
	stbuf->st_size	       = attr->size;
	stbuf->st_atime	       = attr->atime;
	stbuf->st_mtime	       = attr->mtime;
	stbuf->st_ctime        = attr->ctime;
	ST_ATIM_NSEC_SET(stbuf, attr->atimensec);
	ST_MTIM_NSEC_SET(stbuf, attr->mtimensec);
	ST_CTIM_NSEC_SET(stbuf, attr->ctimensec);
}

static void rfuse_convert_statfs(const struct statvfs *stbuf,
			   struct fuse_kstatfs *kstatfs)
{
	kstatfs->bsize	 = stbuf->f_bsize;
	kstatfs->frsize	 = stbuf->f_frsize;
	kstatfs->blocks	 = stbuf->f_blocks;
	kstatfs->bfree	 = stbuf->f_bfree;
	kstatfs->bavail	 = stbuf->f_bavail;
	kstatfs->files	 = stbuf->f_files;
	kstatfs->ffree	 = stbuf->f_ffree;
	kstatfs->namelen = stbuf->f_namemax;
}

static void rfuse_fill_open(struct fuse_open_out *arg,
		      const struct fuse_file_info *f)
{
	arg->fh = f->fh;
	if (f->direct_io)
		arg->open_flags |= FOPEN_DIRECT_IO;
	if (f->keep_cache)
		arg->open_flags |= FOPEN_KEEP_CACHE;
	if (f->cache_readdir)
		arg->open_flags |= FOPEN_CACHE_DIR;
	if (f->nonseekable)
		arg->open_flags |= FOPEN_NONSEEKABLE;
}

static void rfuse_fill_entry(struct fuse_entry_out *arg,
		       const struct fuse_entry_param *e){
	arg->nodeid = e->ino;
	arg->generation = e->generation;
	arg->entry_valid = rfuse_calc_timeout_sec(e->entry_timeout);
	arg->entry_valid_nsec = rfuse_calc_timeout_nsec(e->entry_timeout);
	arg->attr_valid = rfuse_calc_timeout_sec(e->attr_timeout);
	arg->attr_valid_nsec = rfuse_calc_timeout_nsec(e->attr_timeout);
	rfuse_convert_stat(&e->attr, &arg->attr);
}

/* `buf` is allowed to be empty so that the proper size may be
   allocated by the caller */
size_t fuse_add_direntry(fuse_req_t u_req, char *buf, size_t bufsize,
			 const char *name, const struct stat *stbuf, off_t off)
{
	(void)u_req;
	size_t namelen;
	size_t entlen;
	size_t entlen_padded;
	struct fuse_dirent *dirent;

	namelen = strlen(name);
	entlen = FUSE_NAME_OFFSET + namelen;
	entlen_padded = FUSE_DIRENT_ALIGN(entlen);

	if ((buf == NULL) || (entlen_padded > bufsize))
	  return entlen_padded;

	dirent = (struct fuse_dirent*) buf;
	dirent->ino = stbuf->st_ino;
	dirent->off = off;
	dirent->namelen = namelen;
	dirent->type = (stbuf->st_mode & S_IFMT) >> 12;
	memcpy(dirent->name, name, namelen);
	memset(dirent->name + namelen, 0, entlen_padded - entlen);
	return entlen_padded;
}

size_t fuse_add_direntry_plus(fuse_req_t req, char *buf, size_t bufsize,
			      const char *name,
			      const struct fuse_entry_param *e, off_t off)
{
	(void)req;
	size_t namelen;
	size_t entlen;
	size_t entlen_padded;

	namelen = strlen(name);
	entlen = FUSE_NAME_OFFSET_DIRENTPLUS + namelen;
	entlen_padded = FUSE_DIRENT_ALIGN(entlen);
	if ((buf == NULL) || (entlen_padded > bufsize))
	  return entlen_padded;

	struct fuse_direntplus *dp = (struct fuse_direntplus *) buf;
	memset(&dp->entry_out, 0, sizeof(dp->entry_out));
	rfuse_fill_entry(&dp->entry_out, e);

	struct fuse_dirent *dirent = &dp->dirent;
	dirent->ino = e->attr.st_ino;
	dirent->off = off;
	dirent->namelen = namelen;
	dirent->type = (e->attr.st_mode & S_IFMT) >> 12;
	memcpy(dirent->name, name, namelen);
	memset(dirent->name + namelen, 0, entlen_padded - entlen);

	return entlen_padded;
}

// ******************************* Reply to Completion Queue ******************************* //
static int rfuse_send_msg(struct fuse_session *se, fuse_req_t u_req){
		struct rfuse_iqueue *riq = u_req->riq;
		struct rfuse_req *r_req;
		unsigned long tmp_flags;
		assert(se != NULL); // Pass if only session is not NULL

		r_req = &riq->ureq[u_req->index];
		tmp_flags = RFUSE_READ_ONCE(r_req->flags);
		SET_BIT(tmp_flags, FR_FINISHED);
		RFUSE_WRITE_ONCE(r_req->flags, tmp_flags);
		rfuse_smp_mb();
		GET_TIMESTAMPS(5)

		// synchronous request completion reply	
		if(TEST_BIT(tmp_flags, FR_NEEDWAKEUP) && !TEST_BIT(tmp_flags, FR_BACKGROUND)) {
			struct ioctl_args {
				int riq_id;
				int req_index;
			} args = { .riq_id = u_req->riq_id, .req_index = u_req->index };
			ioctl(se->fd, RFUSE_WAKE_UP_COMP, &args);
		}

		// asynchronous background request completion reply	
		if(TEST_BIT(tmp_flags, FR_BACKGROUND)) {
			GET_TIMESTAMPS(5)

			struct ioctl_args {
				int riq_id;
				int req_index;
			} args = { .riq_id = u_req->riq_id, .req_index = u_req->index };
			ioctl(se->fd, RFUSE_REPLY_ASYNC, &args);
			
			return 0;
		}

#ifdef DEBUG
	/* print timestamps */
	for(int i = 2; i <= 5; i++)
		printf("rfuse experiment [%d]: %lu nsec\n", i, timestamps[i]);
#endif

		return 0;
}

static int rfuse_send_reply_iov_nofree(fuse_req_t u_req, int error){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];

	if(error <= -1000 || error > 0){
		fuse_log(FUSE_LOG_ERR, "fuse bad error value: %i\n", error);
		error = -ERANGE;
	}
	r_req->out.error = error;

	return rfuse_send_msg(u_req->se, u_req);
}

static int rfuse_send_reply_iov(fuse_req_t u_req, int error){
	int res;

	GET_TIMESTAMPS(4)
	res = rfuse_send_reply_iov_nofree(u_req,error);
	rfuse_free_req(u_req);
	return res;
}

// out_arg should have the out argument index of "argument buffer"
static int rfuse_send_reply(fuse_req_t u_req, int error){
	return rfuse_send_reply_iov(u_req,error);
}

int fuse_reply_err(fuse_req_t u_req, int err){
	return rfuse_send_reply(u_req, -err);
}

void fuse_reply_none(fuse_req_t u_req){
	rfuse_free_req(u_req);
}

static int rfuse_send_reply_ok(fuse_req_t u_req){
	return rfuse_send_reply(u_req, 0);
}

int fuse_reply_buf(fuse_req_t u_req, const char *buf, size_t size){
	// Write to the kernel buffer
	struct fuse_chan *ch = u_req->ch;
	struct fuse_session *se = u_req->se;
	int req_index = u_req->index;
	int riq_id = u_req->riq->riq_id;
	long long int pp_req_index = ((long long int)req_index << 32) & RFUSE_REQ_IDX_MASK;
	int pp_riq_id = (riq_id << 16) & RFUSE_RIQ_ID_MASK;

	ssize_t res = pwrite(ch ? ch->fd : se->fd, buf, size, (long long int)pp_riq_id | pp_req_index);
	int err = errno;
	if(res == -1){
		if(!fuse_session_exited(se) && err != ENOENT)
			perror("RFUSE ERROR: writing to the device failed!!");
		return -err;
	}
	// Queue to the complete queue
	return rfuse_send_reply_ok(u_req);
}

int fuse_reply_statfs(fuse_req_t u_req, const struct statvfs *stbuf){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_statfs_out *arg = (struct fuse_statfs_out*)&r_req->args;
	
	rfuse_convert_statfs(stbuf, &arg->st);

	return rfuse_send_reply_ok(u_req);
}

int fuse_reply_write(fuse_req_t u_req, size_t count){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_write_out *arg = (struct fuse_write_out *)&r_req->args;
	
	arg->size = count;

	return rfuse_send_reply_ok(u_req);
}

int fuse_reply_attr(fuse_req_t req, const struct stat *attr, double attr_timeout){	
	struct rfuse_iqueue *riq = req->riq;
	struct rfuse_req *r_req = &riq->ureq[req->index];
	struct fuse_attr_out *arg= (struct fuse_attr_out *)&r_req->args;

	memset(arg, 0, sizeof(struct fuse_attr_out));
	arg->attr_valid = rfuse_calc_timeout_sec(attr_timeout);
	arg->attr_valid_nsec = rfuse_calc_timeout_nsec(attr_timeout);
	rfuse_convert_stat(attr, &arg->attr);
	return rfuse_send_reply_ok(req); // queue in the completion queue
}

int fuse_reply_entry(fuse_req_t req, const struct fuse_entry_param *e){
	struct rfuse_iqueue *riq = req->riq;
	struct rfuse_req *r_req = &riq->ureq[req->index];
	struct fuse_entry_out *arg = (struct fuse_entry_out*)&riq->uarg[r_req->out.arg];

	size_t size = req->se->conn.proto_minor < 9 ?
		FUSE_COMPAT_ENTRY_OUT_SIZE : sizeof(arg);
	r_req->out.arglen=size;

	/* before ABI 7.4 e->ino == 0 was invalid, only ENOENT meant
	   negative entry */
	if (!e->ino && req->se->conn.proto_minor < 4)
		return fuse_reply_err(req, ENOENT);

	memset(arg, 0, sizeof(struct fuse_entry_out));
	rfuse_fill_entry(arg, e);
	return rfuse_send_reply_ok(req);
}

int fuse_reply_create(fuse_req_t u_req, const struct fuse_entry_param *e,
		      const struct fuse_file_info *f){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];			  

	struct fuse_entry_out *earg = (struct fuse_entry_out*)&riq->uarg[r_req->out.arg];
	struct fuse_open_out *oarg = (struct fuse_open_out *)&r_req->args;
	
	memset(earg, 0, sizeof(struct fuse_entry_out));
	memset(oarg, 0, sizeof(struct fuse_open_out));
	rfuse_fill_entry(earg, e);
	rfuse_fill_open(oarg, f);

	return rfuse_send_reply_ok(u_req);
}

int fuse_reply_open(fuse_req_t u_req, const struct fuse_file_info *f){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];		
	struct fuse_open_out *arg = (struct fuse_open_out *) &r_req->args;

	memset(arg, 0, sizeof(struct fuse_open_out));
	rfuse_fill_open(arg, f);

	return rfuse_send_reply_ok(u_req);
}

int fuse_reply_readlink(fuse_req_t req, const char *link) {
	return fuse_reply_buf(req, link, strlen(link));
}

int fuse_reply_xattr(fuse_req_t req, size_t count) {
	(void)count;
	return rfuse_send_reply(req, -EOPNOTSUPP);
}

int fuse_reply_lock(fuse_req_t req, const struct flock *lock) {
	(void)lock;
	return rfuse_send_reply(req, -EOPNOTSUPP);
}

int fuse_reply_bmap(fuse_req_t req, uint64_t idx) {
	(void)idx;
	return rfuse_send_reply(req, -EOPNOTSUPP);
}

int fuse_reply_ioctl(fuse_req_t req, int result, const void *buf, size_t size) {
	(void)result; (void)buf; (void)size;
	return rfuse_send_reply(req, -EOPNOTSUPP);
}

int fuse_reply_lseek(fuse_req_t req, off_t off) {
	(void)off;
	return rfuse_send_reply(req, -EOPNOTSUPP);
}

int fuse_reply_poll(fuse_req_t req, unsigned revents) {
	(void)revents;
	return rfuse_send_reply(req, -EOPNOTSUPP);
}

// ******************************* Rfuse Lowlevel operations ******************************* //
void fuse_req_interrupt_func(fuse_req_t req, fuse_interrupt_func_t func,
			     void *data)
{
	pthread_mutex_lock(&req->lock);
	pthread_mutex_lock(&req->se->lock);
	req->u.ni.func = func;
	req->u.ni.data = data;
	pthread_mutex_unlock(&req->se->lock);
	if (req->interrupted && func)
		func(req, data);
	pthread_mutex_unlock(&req->lock);
}

static void rfuse_do_lookup(fuse_req_t u_req, fuse_ino_t nodeid){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];

	char *name = (char *)&riq->uarg[r_req->in.arg[0]];
	if (u_req->se->op.lookup)
		u_req->se->op.lookup(u_req, nodeid, name);
	else
		fuse_reply_err(u_req, ENOSYS);
}

static void rfuse_do_getattr(fuse_req_t u_req, fuse_ino_t nodeid){
	struct fuse_file_info *fip = NULL;
	struct fuse_file_info fi;

	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];

	if(u_req->se->conn.proto_minor >= 9){
		struct fuse_getattr_in *arg = (struct fuse_getattr_in*)&r_req->args;

		if(arg->getattr_flags & FUSE_GETATTR_FH){
			memset(&fi, 0, sizeof(fi));
			fi.fh = arg->fh;
			fip = &fi;
		}
	}

	if (u_req->se->op.getattr)
		u_req->se->op.getattr(u_req, nodeid, fip);
	else
		fuse_reply_err(u_req, ENOSYS);
}

static void rfuse_do_setattr(fuse_req_t u_req, fuse_ino_t nodeid){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];

	struct fuse_setattr_in *arg = (struct fuse_setattr_in *)&r_req->args;

	if (u_req->se->op.setattr) {
		struct fuse_file_info *fi = NULL;
		struct fuse_file_info fi_store;
		struct stat stbuf;
		memset(&stbuf, 0, sizeof(stbuf));
		rfuse_convert_attr(arg, &stbuf);
		if (arg->valid & FATTR_FH) {
			arg->valid &= ~FATTR_FH;
			memset(&fi_store, 0, sizeof(fi_store));
			fi = &fi_store;
			fi->fh = arg->fh;
		}
		arg->valid &=
			FUSE_SET_ATTR_MODE	|
			FUSE_SET_ATTR_UID	|
			FUSE_SET_ATTR_GID	|
			FUSE_SET_ATTR_SIZE	|
			FUSE_SET_ATTR_ATIME	|
			FUSE_SET_ATTR_MTIME	|
			FUSE_SET_ATTR_ATIME_NOW	|
			FUSE_SET_ATTR_MTIME_NOW |
			FUSE_SET_ATTR_CTIME;

		u_req->se->op.setattr(u_req, nodeid, &stbuf, arg->valid, fi);
	} else
		fuse_reply_err(u_req, ENOSYS);
}

static void rfuse_do_rmdir(fuse_req_t u_req, fuse_ino_t nodeid){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];

	char *name = (char *)&riq->uarg[r_req->in.arg[0]];
	if(u_req->se->op.rmdir)
		u_req->se->op.rmdir(u_req,nodeid,name);
	else
		fuse_reply_err(u_req,ENOSYS);

}

static void rfuse_do_rename(fuse_req_t u_req, fuse_ino_t nodeid){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];

	struct fuse_rename_in *arg = (struct fuse_rename_in *) &r_req->args;
	char *oldname = (char *)&riq->uarg[r_req->in.arg[0]];
	char *newname = (char *)&riq->uarg[r_req->in.arg[1]];

	if (u_req->se->op.rename)
		u_req->se->op.rename(u_req, nodeid, oldname, arg->newdir, newname,
				  0);
	else
		fuse_reply_err(u_req, ENOSYS);
}

static void rfuse_do_rename2(fuse_req_t u_req, fuse_ino_t nodeid){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];

	struct fuse_rename2_in *arg = (struct fuse_rename2_in *) &r_req->args;
	char *oldname = (char *)&riq->uarg[r_req->in.arg[0]];
	char *newname = (char *)&riq->uarg[r_req->in.arg[1]];

	if (u_req->se->op.rename)
		u_req->se->op.rename(u_req, nodeid, oldname, arg->newdir, newname,
				  arg->flags);
	else
		fuse_reply_err(u_req, ENOSYS);
}

static void rfuse_do_mkdir(fuse_req_t u_req, fuse_ino_t nodeid){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_mkdir_in *arg = (struct fuse_mkdir_in *)&r_req->args;
	char *name = (char *)&riq->uarg[r_req->in.arg[0]];

	// if (u_req->se->conn.proto_minor >= 12)
	// 	u_req->ctx.umask = arg->umask;

	if (u_req->se->op.mkdir)
		u_req->se->op.mkdir(u_req, nodeid, name, arg->mode);
	else
		fuse_reply_err(u_req, ENOSYS);
}

static void rfuse_do_statfs(fuse_req_t u_req, fuse_ino_t nodeid){
	(void) nodeid;

	if (u_req->se->op.statfs)
		u_req->se->op.statfs(u_req, nodeid);
	else {
		struct statvfs buf = {
			.f_namemax = 255,
			.f_bsize = 512,
		};
		fuse_reply_statfs(u_req, &buf);
	}
}

static void rfuse_do_fsyncdir(fuse_req_t u_req, fuse_ino_t nodeid)
{
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_fsync_in *arg = (struct fuse_fsync_in *)&r_req->args;
	struct fuse_file_info fi;
	int datasync = arg->fsync_flags & 1;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;

	if (u_req->se->op.fsyncdir)
		u_req->se->op.fsyncdir(u_req, nodeid, datasync, &fi);
	else
		fuse_reply_err(u_req, ENOSYS);
}

static void rfuse_do_flush(fuse_req_t u_req, fuse_ino_t nodeid)
{
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_flush_in *arg = (struct fuse_flush_in *)&r_req->args;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.flush = 1;
	if (u_req->se->conn.proto_minor >= 7)
		fi.lock_owner = arg->lock_owner;

	if (u_req->se->op.flush)
		u_req->se->op.flush(u_req, nodeid, &fi);
	else
		fuse_reply_err(u_req, ENOSYS);
}

static void rfuse_do_fsync(fuse_req_t u_req, fuse_ino_t nodeid){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_fsync_in *arg = (struct fuse_fsync_in *)&r_req->args;
	struct fuse_file_info fi;
	int datasync = arg->fsync_flags & 1;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;

	if (u_req->se->op.fsync)
		u_req->se->op.fsync(u_req, nodeid, datasync, &fi);
	else
		fuse_reply_err(u_req, ENOSYS);
}

static void rfuse_do_create(fuse_req_t u_req, fuse_ino_t nodeid){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_create_in *arg = (struct fuse_create_in *)&r_req->args;


	if (u_req->se->op.create) {
		struct fuse_file_info fi;
		char *name = (char *)&riq->uarg[r_req->in.arg[0]];

		memset(&fi, 0, sizeof(fi));
		fi.flags = arg->flags;


		u_req->se->op.create(u_req, nodeid, name, arg->mode, &fi);
	} else
		fuse_reply_err(u_req, ENOSYS);
}

static void rfuse_do_open(fuse_req_t u_req, fuse_ino_t nodeid){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_open_in *arg = (struct fuse_open_in *)&r_req->args;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = arg->flags;

	if (u_req->se->op.open)
		u_req->se->op.open(u_req, nodeid, &fi);
	else
		fuse_reply_open(u_req, &fi);
}

static void rfuse_do_opendir(fuse_req_t u_req, fuse_ino_t nodeid){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_open_in *arg = (struct fuse_open_in *)&r_req->args;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = arg->flags;


	if (u_req->se->op.opendir)
		u_req->se->op.opendir(u_req, nodeid, &fi);
	else
		fuse_reply_open(u_req, &fi);
}

static void rfuse_do_release(fuse_req_t u_req, fuse_ino_t nodeid)
{
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_release_in *arg = (struct fuse_release_in *)&r_req->args;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = arg->flags;
	fi.fh = arg->fh;
	if (u_req->se->conn.proto_minor >= 8) {
		fi.flush = (arg->release_flags & FUSE_RELEASE_FLUSH) ? 1 : 0;
		fi.lock_owner = arg->lock_owner;
	}
	if (arg->release_flags & FUSE_RELEASE_FLOCK_UNLOCK) {
		fi.flock_release = 1;
		fi.lock_owner = arg->lock_owner;
	}

	if (u_req->se->op.release)
		u_req->se->op.release(u_req, nodeid, &fi);
	else
		fuse_reply_err(u_req, 0);
}

static void rfuse_do_releasedir(fuse_req_t u_req, fuse_ino_t nodeid)
{
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_release_in *arg = (struct fuse_release_in *)&r_req->args;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.flags = arg->flags;
	fi.fh = arg->fh;

	if (u_req->se->op.releasedir)
		u_req->se->op.releasedir(u_req, nodeid, &fi);
	else
		fuse_reply_err(u_req, 0);
}


static void rfuse_do_unlink(fuse_req_t u_req, fuse_ino_t nodeid){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];

	char *name = (char *)&riq->uarg[r_req->in.arg[0]];

	if (u_req->se->op.unlink)
		u_req->se->op.unlink(u_req, nodeid, name);
	else
		fuse_reply_err(u_req, ENOSYS);
}


/* Prevent bogus data races (bogus since "init" is called before
 * multi-threading becomes relevant */
static __attribute__((no_sanitize("thread")))
void rfuse_do_init(fuse_req_t u_req, fuse_ino_t nodeid){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_init_in *arg = (struct fuse_init_in *)&r_req->args; 
	struct fuse_init_out *outarg = (struct fuse_init_out *)((char*)&r_req->args + sizeof(struct fuse_init_in)); 
	struct fuse_session *se = u_req->se;
	size_t bufsize = se->bufsize;

	(void) nodeid;
	if (se->debug) {
		fuse_log(FUSE_LOG_DEBUG, "INIT: %u.%u\n", arg->major, arg->minor);
		if (arg->major == 7 && arg->minor >= 6) {
			fuse_log(FUSE_LOG_DEBUG, "flags=0x%08x\n", arg->flags);
			fuse_log(FUSE_LOG_DEBUG, "max_readahead=0x%08x\n",
				arg->max_readahead);
		}
	}
	se->conn.proto_major = arg->major;
	se->conn.proto_minor = arg->minor;
	se->conn.capable = 0;
	se->conn.want = 0;

	outarg->major = FUSE_KERNEL_VERSION;
	outarg->minor = FUSE_KERNEL_MINOR_VERSION;

	if (arg->major < 7) {
		fuse_log(FUSE_LOG_ERR, "fuse: unsupported protocol version: %u.%u\n",
			arg->major, arg->minor);
		fuse_reply_err(u_req, EPROTO);
		return;
	}

	if (arg->major > 7) {
		/* Wait for a second INIT request with a 7.X version */
		rfuse_send_reply_ok(u_req);
		return;
	}

	if (arg->minor >= 6) {
		if (arg->max_readahead < se->conn.max_readahead)
			se->conn.max_readahead = arg->max_readahead;
		if (arg->flags & FUSE_ASYNC_READ)
			se->conn.capable |= FUSE_CAP_ASYNC_READ;
		if (arg->flags & FUSE_POSIX_LOCKS)
			se->conn.capable |= FUSE_CAP_POSIX_LOCKS;
		if (arg->flags & FUSE_ATOMIC_O_TRUNC)
			se->conn.capable |= FUSE_CAP_ATOMIC_O_TRUNC;
		if (arg->flags & FUSE_EXPORT_SUPPORT)
			se->conn.capable |= FUSE_CAP_EXPORT_SUPPORT;
		if (arg->flags & FUSE_DONT_MASK)
			se->conn.capable |= FUSE_CAP_DONT_MASK;
		if (arg->flags & FUSE_FLOCK_LOCKS)
			se->conn.capable |= FUSE_CAP_FLOCK_LOCKS;
		if (arg->flags & FUSE_AUTO_INVAL_DATA)
			se->conn.capable |= FUSE_CAP_AUTO_INVAL_DATA;
		if (arg->flags & FUSE_DO_READDIRPLUS)
			se->conn.capable |= FUSE_CAP_READDIRPLUS;
		if (arg->flags & FUSE_READDIRPLUS_AUTO)
			se->conn.capable |= FUSE_CAP_READDIRPLUS_AUTO;
		if (arg->flags & FUSE_ASYNC_DIO)
			se->conn.capable |= FUSE_CAP_ASYNC_DIO;
		if (arg->flags & FUSE_WRITEBACK_CACHE)
			se->conn.capable |= FUSE_CAP_WRITEBACK_CACHE;
		if (arg->flags & FUSE_NO_OPEN_SUPPORT)
			se->conn.capable |= FUSE_CAP_NO_OPEN_SUPPORT;
		if (arg->flags & FUSE_PARALLEL_DIROPS)
			se->conn.capable |= FUSE_CAP_PARALLEL_DIROPS;
		if (arg->flags & FUSE_POSIX_ACL)
			se->conn.capable |= FUSE_CAP_POSIX_ACL;
		if (arg->flags & FUSE_HANDLE_KILLPRIV)
			se->conn.capable |= FUSE_CAP_HANDLE_KILLPRIV;
		if (arg->flags & FUSE_CACHE_SYMLINKS)
			se->conn.capable |= FUSE_CAP_CACHE_SYMLINKS;
		if (arg->flags & FUSE_NO_OPENDIR_SUPPORT)
			se->conn.capable |= FUSE_CAP_NO_OPENDIR_SUPPORT;
		if (arg->flags & FUSE_EXPLICIT_INVAL_DATA)
			se->conn.capable |= FUSE_CAP_EXPLICIT_INVAL_DATA;
		if (!(arg->flags & FUSE_MAX_PAGES)) {
			size_t max_bufsize =
				FUSE_DEFAULT_MAX_PAGES_PER_REQ * getpagesize()
				+ FUSE_BUFFER_HEADER_SIZE;
			if (bufsize > max_bufsize) {
				bufsize = max_bufsize;
			}
		}
	} else {
		se->conn.max_readahead = 0;
	}

	if (se->conn.proto_minor >= 14) {
#ifdef HAVE_SPLICE
		se->conn.capable |= FUSE_CAP_SPLICE_WRITE | FUSE_CAP_SPLICE_MOVE;
		se->conn.capable |= FUSE_CAP_SPLICE_READ;
#endif
	}
	if (se->conn.proto_minor >= 18)
		se->conn.capable |= FUSE_CAP_IOCTL_DIR;

	/* Default settings for modern filesystems.
	 *
	 * Most of these capabilities were disabled by default in
	 * libfuse2 for backwards compatibility reasons. In libfuse3,
	 * we can finally enable them by default (as long as they're
	 * supported by the kernel).
	 */
#define LL_SET_DEFAULT(cond, cap) \
	if ((cond) && (se->conn.capable & (cap))) \
		se->conn.want |= (cap)
	LL_SET_DEFAULT(1, FUSE_CAP_ASYNC_READ);
	LL_SET_DEFAULT(1, FUSE_CAP_PARALLEL_DIROPS);
	LL_SET_DEFAULT(1, FUSE_CAP_AUTO_INVAL_DATA);
	LL_SET_DEFAULT(1, FUSE_CAP_HANDLE_KILLPRIV);
	LL_SET_DEFAULT(1, FUSE_CAP_ASYNC_DIO);
	LL_SET_DEFAULT(1, FUSE_CAP_IOCTL_DIR);
	LL_SET_DEFAULT(1, FUSE_CAP_ATOMIC_O_TRUNC);
	LL_SET_DEFAULT(se->op.write_buf, FUSE_CAP_SPLICE_READ);
	LL_SET_DEFAULT(se->op.getlk && se->op.setlk,
		       FUSE_CAP_POSIX_LOCKS);
	LL_SET_DEFAULT(se->op.flock, FUSE_CAP_FLOCK_LOCKS);
	LL_SET_DEFAULT(se->op.readdirplus, FUSE_CAP_READDIRPLUS);
	LL_SET_DEFAULT(se->op.readdirplus && se->op.readdir,
		       FUSE_CAP_READDIRPLUS_AUTO);
	se->conn.time_gran = 1;
	
	if (bufsize < FUSE_MIN_READ_BUFFER) {
		fuse_log(FUSE_LOG_ERR, "fuse: warning: buffer size too small: %zu\n",
			bufsize);
		bufsize = FUSE_MIN_READ_BUFFER;
	}
	se->bufsize = bufsize;

	if (se->conn.max_write > bufsize - FUSE_BUFFER_HEADER_SIZE)
		se->conn.max_write = bufsize - FUSE_BUFFER_HEADER_SIZE;

	se->got_init = 1;
	if (se->op.init)
		se->op.init(se->userdata, &se->conn);

	if (se->conn.want & (~se->conn.capable)) {
		fuse_log(FUSE_LOG_ERR, "fuse: error: filesystem requested capabilities "
			"0x%x that are not supported by kernel, aborting.\n",
			se->conn.want & (~se->conn.capable));
		fuse_reply_err(u_req, EPROTO);
		se->error = -EPROTO;
		fuse_session_exit(se);
		return;
	}

	unsigned max_read_mo = get_max_read(se->mo);
	if (se->conn.max_read != max_read_mo) {
		fuse_log(FUSE_LOG_ERR, "fuse: error: init() and fuse_session_new() "
			"requested different maximum read size (%u vs %u)\n",
			se->conn.max_read, max_read_mo);
		fuse_reply_err(u_req, EPROTO);
		se->error = -EPROTO;
		fuse_session_exit(se);
		return;
	}

	if (se->conn.max_write < bufsize - FUSE_BUFFER_HEADER_SIZE) {
		se->bufsize = se->conn.max_write + FUSE_BUFFER_HEADER_SIZE;
	}
	if (arg->flags & FUSE_MAX_PAGES) {
		outarg->flags |= FUSE_MAX_PAGES;
		outarg->max_pages = (se->conn.max_write - 1) / getpagesize() + 1;
	}

	/* Always enable big writes, this is superseded
	   by the max_write option */
	outarg->flags |= FUSE_BIG_WRITES;

	if (se->conn.want & FUSE_CAP_ASYNC_READ)
		outarg->flags |= FUSE_ASYNC_READ;
	if (se->conn.want & FUSE_CAP_POSIX_LOCKS)
		outarg->flags |= FUSE_POSIX_LOCKS;
	if (se->conn.want & FUSE_CAP_ATOMIC_O_TRUNC)
		outarg->flags |= FUSE_ATOMIC_O_TRUNC;
	if (se->conn.want & FUSE_CAP_EXPORT_SUPPORT)
		outarg->flags |= FUSE_EXPORT_SUPPORT;
	if (se->conn.want & FUSE_CAP_DONT_MASK)
		outarg->flags |= FUSE_DONT_MASK;
	if (se->conn.want & FUSE_CAP_FLOCK_LOCKS)
		outarg->flags |= FUSE_FLOCK_LOCKS;
	if (se->conn.want & FUSE_CAP_AUTO_INVAL_DATA)
		outarg->flags |= FUSE_AUTO_INVAL_DATA;
	if (se->conn.want & FUSE_CAP_READDIRPLUS)
		outarg->flags |= FUSE_DO_READDIRPLUS;
	if (se->conn.want & FUSE_CAP_READDIRPLUS_AUTO)
		outarg->flags |= FUSE_READDIRPLUS_AUTO;
	if (se->conn.want & FUSE_CAP_ASYNC_DIO)
		outarg->flags |= FUSE_ASYNC_DIO;
	if (se->conn.want & FUSE_CAP_WRITEBACK_CACHE)
		outarg->flags |= FUSE_WRITEBACK_CACHE;
	if (se->conn.want & FUSE_CAP_POSIX_ACL)
		outarg->flags |= FUSE_POSIX_ACL;
	if (se->conn.want & FUSE_CAP_CACHE_SYMLINKS)
		outarg->flags |= FUSE_CACHE_SYMLINKS;
	if (se->conn.want & FUSE_CAP_EXPLICIT_INVAL_DATA)
		outarg->flags |= FUSE_EXPLICIT_INVAL_DATA;

	se->conn.want |= FUSE_CAP_SPLICE_WRITE | FUSE_CAP_SPLICE_MOVE;

	outarg->flags |= FUSE_PARALLEL_DIROPS;
	outarg->max_readahead = se->conn.max_readahead;
	outarg->max_write = se->conn.max_write;
	if (se->conn.proto_minor >= 13) {
		if (se->conn.max_background >= (1 << 16))
			se->conn.max_background = (1 << 16) - 1;
		if (se->conn.congestion_threshold > se->conn.max_background)
			se->conn.congestion_threshold = se->conn.max_background;
		if (!se->conn.congestion_threshold) {
			se->conn.congestion_threshold =
				se->conn.max_background * 3 / 4;
		}

		outarg->max_background = se->conn.max_background;
		outarg->congestion_threshold = se->conn.congestion_threshold;
	}
	if (se->conn.proto_minor >= 23)
		outarg->time_gran = se->conn.time_gran;

	if (se->debug) {
		fuse_log(FUSE_LOG_DEBUG, "   INIT: %u.%u\n", outarg->major, outarg->minor);
		fuse_log(FUSE_LOG_DEBUG, "   flags=0x%08x\n", outarg->flags);
		fuse_log(FUSE_LOG_DEBUG, "   max_readahead=0x%08x\n",
			outarg->max_readahead);
		fuse_log(FUSE_LOG_DEBUG, "   max_write=0x%08x\n", outarg->max_write);
		fuse_log(FUSE_LOG_DEBUG, "   max_background=%i\n",
			outarg->max_background);
		fuse_log(FUSE_LOG_DEBUG, "   congestion_threshold=%i\n",
			outarg->congestion_threshold);
		fuse_log(FUSE_LOG_DEBUG, "   time_gran=%u\n",
			outarg->time_gran);
	}
	
	rfuse_send_reply_ok(u_req);
}

static void rfuse_do_forget(fuse_req_t u_req, fuse_ino_t nodeid)
{
	if (u_req->se->op.forget)
		u_req->se->op.forget(u_req, nodeid, u_req->nlookup);
	else
		fuse_reply_none(u_req);
}

static void rfuse_do_write(fuse_req_t u_req, fuse_ino_t nodeid){
	int res = 0;
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_session *se = u_req->se;
	struct fuse_chan *ch = u_req->ch;
	struct fuse_write_in *arg = (struct fuse_write_in *)&r_req->args;
	struct fuse_file_info fi;
	char *param;
	int req_index = u_req->index;
	int riq_id = u_req->riq->riq_id;
	long long int pp_req_index = ((long long int)req_index << 32) & RFUSE_REQ_IDX_MASK;
	int pp_riq_id = (riq_id << 16) & RFUSE_RIQ_ID_MASK;
	
	if(!u_req->w->fbuf.mem) {
		u_req->w->fbuf.mem = malloc(FUSE_MAX_MAX_PAGES * getpagesize());
		if(!u_req->w->fbuf.mem) {
			printf("Error : malloc for write I/O failed\n");
			fuse_reply_err(u_req, EIO);
		}
		u_req->w->fbuf.size = FUSE_MAX_MAX_PAGES * getpagesize();
	}

	// 1.Call a system call to receive the data from the kernel page
	res = pread(ch ? ch->fd : se->fd, u_req->w->fbuf.mem, u_req->w->fbuf.size, (long long int)pp_riq_id | pp_req_index);
	if(res == -1) {
		printf("Error : pread for write I/O failed\n");
		fuse_reply_err(u_req, EIO);
	}

	// 2. Call "u_req->se->op.write" to process write
	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.writepage = (arg->write_flags & FUSE_WRITE_CACHE) != 0;
	if (u_req->se->conn.proto_minor >= 9) {
		fi.lock_owner = arg->lock_owner;
		fi.flags = arg->flags;
	}
	param = (char *)u_req->w->fbuf.mem;

	if (u_req->se->op.write)
		u_req->se->op.write(u_req, nodeid, param, res,
				arg->offset, &fi);
	else
		fuse_reply_err(u_req, ENOSYS);
	
}

static size_t pagesize;

static __attribute__((constructor)) void fuse_ll_init_pagesize(void)
{
	pagesize = getpagesize();
}

struct fuse_ll_pipe {
	size_t size;
	int can_grow;
	int pipe[2];
};

static void fuse_ll_pipe_free(struct fuse_ll_pipe *llp)
{
	close(llp->pipe[0]);
	close(llp->pipe[1]);
	free(llp);
}

#ifdef HAVE_SPLICE
#if !defined(HAVE_PIPE2) || !defined(O_CLOEXEC)
static int fuse_pipe(int fds[2])
{
	int rv = pipe(fds);

	if (rv == -1)
		return rv;

	if (fcntl(fds[0], F_SETFL, O_NONBLOCK) == -1 ||
	    fcntl(fds[1], F_SETFL, O_NONBLOCK) == -1 ||
	    fcntl(fds[0], F_SETFD, FD_CLOEXEC) == -1 ||
	    fcntl(fds[1], F_SETFD, FD_CLOEXEC) == -1) {
		close(fds[0]);
		close(fds[1]);
		rv = -1;
	}
	return rv;
}
#else
static int fuse_pipe(int fds[2])
{
	return pipe2(fds, O_CLOEXEC | O_NONBLOCK);
}
#endif

static struct fuse_ll_pipe *fuse_ll_get_pipe(struct fuse_session *se)
{
	struct fuse_ll_pipe *llp = pthread_getspecific(se->pipe_key);
	if (llp == NULL) {
		int res;

		llp = malloc(sizeof(struct fuse_ll_pipe));
		if (llp == NULL)
			return NULL;

		res = fuse_pipe(llp->pipe);
		if (res == -1) {
			free(llp);
			return NULL;
		}

		/*
		 *the default size is 16 pages on linux
		 */
		llp->size = pagesize * 16;
		llp->can_grow = 1;

		pthread_setspecific(se->pipe_key, llp);
	}

	return llp;
}
#endif

static void fuse_ll_clear_pipe(struct fuse_session *se)
{
	struct fuse_ll_pipe *llp = pthread_getspecific(se->pipe_key);
	if (llp) {
		pthread_setspecific(se->pipe_key, NULL);
		fuse_ll_pipe_free(llp);
	}
}

#if defined(HAVE_SPLICE)
static int grow_pipe_to_max(int pipefd)
{
	int max;
	int res;
	int maxfd;
	char buf[32];

	maxfd = open("/proc/sys/fs/pipe-max-size", O_RDONLY);
	if (maxfd < 0)
		return -errno;

	res = read(maxfd, buf, sizeof(buf) - 1);
	if (res < 0) {
		int saved_errno;

		saved_errno = errno;
		close(maxfd);
		return -saved_errno;
	}
	close(maxfd);
	buf[res] = '\0';

	max = atoi(buf);
	res = fcntl(pipefd, F_SETPIPE_SZ, max);
	if (res < 0)
		return -errno;
	return max;
}

static int rfuse_send_data_iov(fuse_req_t u_req, struct fuse_bufvec *buf, unsigned int flags)
{
	int res;
	struct fuse_session *se = u_req->se;
	struct fuse_chan *ch = u_req->ch;
	size_t len = fuse_buf_size(buf);
	struct fuse_ll_pipe *llp;
	int splice_flags;
	size_t pipesize;
	size_t total_buf_size;
	size_t idx;
	struct fuse_bufvec pipe_buf = FUSE_BUFVEC_INIT(len);

	long long int pp_req_index = ((long long int)u_req->index << 32) & RFUSE_REQ_IDX_MASK;
	int pp_riq_id = (u_req->riq->riq_id << 16) & RFUSE_RIQ_ID_MASK;
	off64_t off_out = (off64_t)pp_riq_id | pp_req_index;

	if (se->broken_splice_nonblock)
		goto fallback;

	if (flags & FUSE_BUF_NO_SPLICE)
		goto fallback;

	total_buf_size = 0;
	for (idx = buf->idx; idx < buf->count; idx++) {
		total_buf_size += buf->buf[idx].size;
		if (idx == buf->idx)
			total_buf_size -= buf->off;
	}
	
	llp = fuse_ll_get_pipe(se);
	if (llp == NULL)
		goto fallback;

	/*
	 * Heuristic for the required pipe size, does not work if the
	 * source contains less than page size fragments
	 */
	pipesize = pagesize * (buf->count + 1) + len;

	if (llp->size < pipesize) {
		if (llp->can_grow) {
			res = fcntl(llp->pipe[0], F_SETPIPE_SZ, pipesize);
			if (res == -1) {
				res = grow_pipe_to_max(llp->pipe[0]);
				if (res > 0)
					llp->size = res;
				llp->can_grow = 0;
				goto fallback;
			}
			llp->size = res;
		}
		if (llp->size < pipesize)
			goto fallback;
	}

	pipe_buf.buf[0].flags = FUSE_BUF_IS_FD;
	pipe_buf.buf[0].fd = llp->pipe[1];

	res = fuse_buf_copy(&pipe_buf, buf,
			    FUSE_BUF_FORCE_SPLICE | FUSE_BUF_SPLICE_NONBLOCK);
	if (res < 0) {
		if (res == -EAGAIN || res == -EINVAL) {
			/*
			 * Should only get EAGAIN on kernels with
			 * broken SPLICE_F_NONBLOCK support (<=
			 * 2.6.35) where this error or a short read is
			 * returned even if the pipe itself is not
			 * full
			 *
			 * EINVAL might mean that splice can't handle
			 * this combination of input and output.
			 */
			if (res == -EAGAIN)
				se->broken_splice_nonblock = 1;

			pthread_setspecific(se->pipe_key, NULL);
			fuse_ll_pipe_free(llp);
			goto fallback;
		}
		res = -res;
		goto clear_pipe;
	}

	len = res;

	if (se->debug) {
		fuse_log(FUSE_LOG_DEBUG,
			"   success, outsize: %i (splice)\n", len);
	}

	if(len == 0)
		goto no_data;

	splice_flags = 0;
	if ((flags & FUSE_BUF_SPLICE_MOVE) &&
	    (se->conn.want & FUSE_CAP_SPLICE_MOVE)) {
		splice_flags |= SPLICE_F_MOVE;
	}

	/* Use off_out as indicate riq_id and req_index*/
	res = splice(llp->pipe[0], NULL, ch ? ch->fd : se->fd, &off_out, len, splice_flags);
	if (res == -1) {
		res = -errno;
		perror("fuse: splice from pipe");
		goto clear_pipe;
	}
	if (res != len) {
		res = -EIO;
		fuse_log(FUSE_LOG_ERR, "fuse: short splice from pipe: %u/%u\n",
			res, len);
		goto clear_pipe;
	}

	return 0;

no_data:
	fuse_reply_err(u_req, res);
	return RFUSE_SPLICE_READ_NO_DATA;

clear_pipe:
	fuse_ll_clear_pipe(se);
	return res;

fallback:
	return -EIO;
}
#endif

int fuse_reply_data(fuse_req_t u_req, struct fuse_bufvec *bufv,
		    enum fuse_buf_copy_flags flags)
{
	int res;

	res = rfuse_send_data_iov(u_req, bufv, flags);
	if(res == RFUSE_SPLICE_READ_NO_DATA) {
		return res;
	} else if (res == 0) {
		rfuse_free_req(u_req);
		return res;
	} else {
		return fuse_reply_err(u_req, res);
	}
}

static int rfuse_prep_write_buf(fuse_req_t u_req, struct fuse_session *se, struct fuse_buf *buf,
				 struct fuse_chan *ch) {
	int err;
	ssize_t res;
	size_t bufsize = se->bufsize;
	struct fuse_ll_pipe *llp;
	struct fuse_buf tmpbuf;
	long long int pp_req_index = ((long long int)u_req->index << 32) & RFUSE_REQ_IDX_MASK;
	int pp_riq_id = (u_req->riq->riq_id << 16) & RFUSE_RIQ_ID_MASK;
	off64_t off_in = (off64_t)pp_riq_id | pp_req_index;

	llp = fuse_ll_get_pipe(se);
	if (llp == NULL)
		return -EIO;

	if (llp->size < bufsize) {
		if (llp->can_grow) {
			res = fcntl(llp->pipe[0], F_SETPIPE_SZ, bufsize);
			if (res == -1) {
				llp->can_grow = 0;
				res = grow_pipe_to_max(llp->pipe[0]);
				if (res > 0)
					llp->size = res;
				return -EIO; /* fallback to normal write */
			}
			llp->size = res;
		}
		if (llp->size < bufsize)
			return -EIO;
	}

	/* Use off_in as indicate riq_id and req_index*/
	res = splice(ch ? ch->fd : se->fd, &off_in, llp->pipe[1], NULL, bufsize, 0);
	err = errno;

	if (fuse_session_exited(se))
		return 0;

	if (res == -1) {
		if (err == ENODEV) {
			/* Filesystem was unmounted, or connection was aborted
			   via /sys/fs/fuse/connections */
			fuse_session_exit(se);
			return 0;
		}
		if (err != EINTR && err != EAGAIN)
			perror("fuse: splice from device");
		return -err;
	}

	tmpbuf = (struct fuse_buf) {
		.size = res,
		.flags = FUSE_BUF_IS_FD,
		.fd = llp->pipe[0],
	};

	buf->fd = tmpbuf.fd;
	buf->flags = tmpbuf.flags;
	buf->size = tmpbuf.size;

	return res;
}

static void rfuse_do_write_buf(fuse_req_t u_req, fuse_ino_t nodeid,
			 const struct fuse_buf *ibuf)
{
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_session *se = u_req->se;
	struct fuse_bufvec bufv = {
		.buf[0] = *ibuf,
		.count = 1,
	};
	struct fuse_write_in *arg = (struct fuse_write_in *)&r_req->args;
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;
	fi.writepage = arg->write_flags & FUSE_WRITE_CACHE;


	fi.lock_owner = arg->lock_owner;
	fi.flags = arg->flags;

	if (bufv.buf[0].size < arg->size) {
		fuse_log(FUSE_LOG_ERR, "rfuse: rfuse_do_write_buf: buffer size too small\n");
		fuse_reply_err(u_req, EIO);
		goto out;
	}
	bufv.buf[0].size = arg->size;

	se->op.write_buf(u_req, nodeid, &bufv, arg->offset, &fi);

out:
	/* Need to reset the pipe if ->write_buf() didn't consume all data */
	if ((ibuf->flags & FUSE_BUF_IS_FD) && bufv.idx < bufv.count)
		fuse_ll_clear_pipe(se);
}

static void rfuse_do_read(fuse_req_t u_req, fuse_ino_t nodeid){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_read_in *arg = (struct fuse_read_in *)&r_req->args;
	struct fuse_file_info fi;

	if (u_req->se->op.read) {
		memset(&fi, 0, sizeof(fi));
		fi.fh = arg->fh;
		if (u_req->se->conn.proto_minor >= 9) {
			fi.lock_owner = arg->lock_owner;
			fi.flags = arg->flags;
		}

		u_req->se->op.read(u_req, nodeid, arg->size, arg->offset, &fi);
	} else
		fuse_reply_err(u_req, ENOSYS);
	
}	

static void rfuse_do_readdir(fuse_req_t u_req, fuse_ino_t nodeid){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_read_in *arg = (struct fuse_read_in *)&r_req->args;	
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;

	if (u_req->se->op.readdir)
		u_req->se->op.readdir(u_req, nodeid, arg->size, arg->offset, &fi);
	else
		fuse_reply_err(u_req, ENOSYS);
}

static void rfuse_do_readdirplus(fuse_req_t u_req, fuse_ino_t nodeid)
{
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_read_in *arg = (struct fuse_read_in *)&r_req->args;	
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;

	if (u_req->se->op.readdirplus)
		u_req->se->op.readdirplus(u_req, nodeid, arg->size, arg->offset, &fi);
	else
		fuse_reply_err(u_req, ENOSYS);
}

static void rfuse_do_fallocate(fuse_req_t u_req, fuse_ino_t nodeid)
{
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_fallocate_in *arg = (struct fuse_fallocate_in *)&r_req->args;	
	struct fuse_file_info fi;

	memset(&fi, 0, sizeof(fi));
	fi.fh = arg->fh;

	if (u_req->se->op.fallocate)
		u_req->se->op.fallocate(u_req, nodeid, arg->mode, arg->offset, arg->length, &fi);
	else
		fuse_reply_err(u_req, ENOSYS);
}

static void rfuse_do_destroy(fuse_req_t u_req, fuse_ino_t nodeid)
{
	struct fuse_session *se = u_req->se;

	(void) nodeid;

	se->got_destroy = 1;
	/**
	 * Not sure if we can just call fuse session exit here.
	 * Original Fuse always read from the fuse device, and handled the 
	 * connection abort through the erro code "ENODEV" (Device does not exists)
	 * However, Rfuse does not read from a device. So we should just set the 
	 * se->exited to 1 here
	 * 
	 */
	if (se->op.destroy)
		se->op.destroy(se->userdata);

	rfuse_send_reply_ok(u_req);
}

static void rfuse_do_access(fuse_req_t u_req, fuse_ino_t nodeid){
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];
	struct fuse_access_in *arg  = (struct fuse_access_in *)&r_req->args;
	if(u_req->se->op.access){	
		u_req->se->op.access(u_req, nodeid, arg->mask);
	}
	else{
		fuse_reply_err(u_req, ENOSYS);

	}
}

static void rfuse_do_readlink(fuse_req_t u_req, fuse_ino_t nodeid)
{
	if (u_req->se->op.readlink)
		u_req->se->op.readlink(u_req, nodeid);
	else
		fuse_reply_err(u_req, ENOSYS);
}

static void rfuse_do_symlink(fuse_req_t u_req, fuse_ino_t nodeid)
{
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];

	char *name = (char *)&riq->uarg[r_req->in.arg[0]];
	char *linkname = (char *)&riq->uarg[r_req->in.arg[1]];

	if (u_req->se->op.symlink)
		u_req->se->op.symlink(u_req, linkname, nodeid, name);
	else
		fuse_reply_err(u_req, ENOSYS);
}

static void rfuse_do_link(fuse_req_t u_req, fuse_ino_t nodeid)
{
	struct rfuse_iqueue *riq = u_req->riq;
	struct rfuse_req *r_req = &riq->ureq[u_req->index];

	struct fuse_link_in *arg = (struct fuse_link_in *)&r_req->args; 
	char *newname = (char *)&riq->uarg[r_req->in.arg[1]];

	if (u_req->se->op.link)
		u_req->se->op.link(u_req, arg->oldnodeid, nodeid, newname);
	else
		fuse_reply_err(u_req, ENOSYS);
}

static struct {
	void (*func)(fuse_req_t, fuse_ino_t);
	const char *name;
} rfuse_ll_ops[] = {
	[FUSE_LOOKUP]	   = { rfuse_do_lookup,      "LOOKUP"	     },
	[FUSE_FORGET]	   = { rfuse_do_forget,      "FORGET"	     },
	[FUSE_GETATTR]	   = { rfuse_do_getattr,     "GETATTR"     },
	[FUSE_SETATTR]	   = { rfuse_do_setattr,     "SETATTR"     },
	[FUSE_READLINK]	   = { rfuse_do_readlink,    "READLINK"    },
	[FUSE_SYMLINK]	   = { rfuse_do_symlink,     "SYMLINK"     },
	// [FUSE_MKNOD]	   = { do_mknod,       "MKNOD"	     },
	[FUSE_MKDIR]	   = { rfuse_do_mkdir,       "MKDIR"	     },
	[FUSE_UNLINK]	   = { rfuse_do_unlink,      "UNLINK"	     },
	[FUSE_RMDIR]	   = { rfuse_do_rmdir,       "RMDIR"	     },
	[FUSE_RENAME]	   = { rfuse_do_rename,      "RENAME"	     },
	[FUSE_LINK]	   = { rfuse_do_link,	       "LINK"	     },
	[FUSE_OPEN]	   = { rfuse_do_open,	       "OPEN"	     },
	[FUSE_READ]	   = { rfuse_do_read,	       "READ"	     },
	[FUSE_WRITE]	   = { rfuse_do_write,       "WRITE"	     },
	[FUSE_STATFS]	   = { rfuse_do_statfs,      "STATFS"	     },
	[FUSE_RELEASE]	   = { rfuse_do_release,     "RELEASE"     },
	[FUSE_FSYNC]	   = { rfuse_do_fsync,       "FSYNC"	     },
	// [FUSE_SETXATTR]	   = { do_setxattr,    "SETXATTR"    },
	// [FUSE_GETXATTR]	   = { do_getxattr,    "GETXATTR"    },
	// [FUSE_LISTXATTR]   = { do_listxattr,   "LISTXATTR"   },
	// [FUSE_REMOVEXATTR] = { do_removexattr, "REMOVEXATTR" },
	[FUSE_FLUSH]	   = { rfuse_do_flush,       "FLUSH"	     },
	[FUSE_INIT]	   = { rfuse_do_init,	       "INIT"	     },
	[FUSE_OPENDIR]	   = { rfuse_do_opendir,     "OPENDIR"     },
	[FUSE_READDIR]	   = { rfuse_do_readdir,     "READDIR"     },
	[FUSE_RELEASEDIR]  = { rfuse_do_releasedir,  "RELEASEDIR"  },
	[FUSE_FSYNCDIR]	   = { rfuse_do_fsyncdir,    "FSYNCDIR"    },
	// [FUSE_GETLK]	   = { do_getlk,       "GETLK"	     },
	// [FUSE_SETLK]	   = { do_setlk,       "SETLK"	     },
	// [FUSE_SETLKW]	   = { do_setlkw,      "SETLKW"	     },
	// [FUSE_ACCESS]	   = { do_access,      "ACCESS"	     },
	[FUSE_ACCESS]	   = { rfuse_do_access,      "ACCESS"	     },
	[FUSE_CREATE]	   = { rfuse_do_create,      "CREATE"	     },
	// [FUSE_INTERRUPT]   = { do_interrupt,   "INTERRUPT"   },
	// [FUSE_BMAP]	   = { do_bmap,	       "BMAP"	     },
	// [FUSE_IOCTL]	   = { do_ioctl,       "IOCTL"	     },
	// [FUSE_POLL]	   = { do_poll,        "POLL"	     },
	[FUSE_FALLOCATE]   = { rfuse_do_fallocate,   "FALLOCATE"   },
	[FUSE_DESTROY]	   = { rfuse_do_destroy,     "DESTROY"     },
	// [FUSE_NOTIFY_REPLY] = { (void *) 1,    "NOTIFY_REPLY" },
	// [FUSE_BATCH_FORGET] = { do_batch_forget, "BATCH_FORGET" },
	[FUSE_READDIRPLUS] = { rfuse_do_readdirplus,	"READDIRPLUS"},
	[FUSE_RENAME2]     = { rfuse_do_rename2,      "RENAME2"    },
	// [FUSE_COPY_FILE_RANGE] = { do_copy_file_range, "COPY_FILE_RANGE" },
	// [FUSE_LSEEK]	   = { do_lseek,       "LSEEK"	     },
	// [CUSE_INIT]	   = { cuse_lowlevel_init, "CUSE_INIT"   },
};

#define FUSE_MAXOP (sizeof(rfuse_ll_ops) / sizeof(rfuse_ll_ops[0]))

#ifdef DEBUG 
static const char *rfuse_opname(enum fuse_opcode  opcode)
{
	if (opcode >= FUSE_MAXOP || !rfuse_ll_ops[opcode].name)
		return "Not implemented Yet";
	else
		return rfuse_ll_ops[opcode].name;
}
#endif

bool rfuse_read_queue(struct rfuse_worker *w, struct rfuse_mt *mt, struct fuse_chan *ch, int forget) {
/**
 * This function reads an request(or interrupt, forget) from the shared 
 * memory space, and calls the corresponding functions to process it.
 * The original fuse had 'fuse_session_porocess_buf_int' and 'fuse_session
 * _receive_buf' for the same functionality
 * 
 * 1. Determine which queue it's going to look into(not implemented yet)
 * 2. Extract a request(interrupt, pending, etc) from the head(not the tail)
 * 3. Generate a ULR (or Interrupt entry) and queue it (ULR stands for user level request)
 * 4. Call the function (e.g. do_getattr, do_lookup)
 */
 	struct fuse_session *se = mt->se;
	int riq_id = mt->riq_id;
	struct rfuse_iqueue *riq = se->riq[riq_id]; // Iqueue
	struct rfuse_address_entry *target_entry;
	struct rfuse_forget_entry *forget_entry;
	fuse_req_t u_req; // ULR 
	struct rfuse_req *r_req;
	int err;
	uint64_t nodeid;
	bool processed = false;

	if(riq->connected == 0){
		printf("riq connection is lost, id: %d\n", riq_id);
		fuse_session_exit(se);
		return processed;
	}
	
	// 1.Forget Requests
	if(forget == 1){
		pthread_mutex_lock(&se->riq_lock[riq_id]);
		forget_entry = rfuse_read_forgets_head(riq);
		if(!forget_entry){
			pthread_mutex_unlock(&se->riq_lock[riq_id]);
			// rfuse_free_req(u_req);
			goto out;
		}
		u_req = rfuse_ll_alloc_req(se, riq_id);
		u_req->nlookup = forget_entry->nlookup;
		u_req->unique = forget_entry->unique;
		u_req->w = w;
		nodeid = forget_entry->nodeid;
		rfuse_extract_forgets_head(riq);
		pthread_mutex_unlock(&se->riq_lock[riq_id]);
		
		rfuse_ll_ops[FUSE_FORGET].func(u_req,nodeid);
		processed = true;
		return processed;
	}
	else{
		// 2. Pending Requests
		pthread_mutex_lock(&se->riq_lock[riq_id]);
		target_entry = rfuse_read_pending_head(riq);
		if(!target_entry){
			pthread_mutex_unlock(&se->riq_lock[riq_id]);
			// rfuse_free_req(u_req);
			goto out;
		}
		u_req = rfuse_ll_alloc_req(se, riq_id);
		u_req->index = target_entry->request;
		rfuse_extract_pending_head(riq);
		r_req = &riq->ureq[u_req->index];
		assert(r_req->riq_id == u_req->riq_id);
		u_req->w = w;
		rfuse_list_add_req(u_req, &se->rfuse_list[riq_id]);
		pthread_mutex_unlock(&se->riq_lock[riq_id]);
		processed = true;
	}
	
#ifdef DEBUG 
	printf("rfuse experiment opcode: %s (%i)\n", rfuse_opname((enum fuse_opcode) r_req->in.opcode), r_req->in.opcode);
#endif

	GET_TIMESTAMPS(2)
	u_req->unique = r_req->in.unique;
	u_req->ctx.uid = r_req->in.uid;
	u_req->ctx.gid = r_req->in.gid;
	u_req->ctx.pid = r_req->in.pid;
	u_req->ch = ch ? fuse_chan_get(ch) : NULL;
	err = EIO;
	if(!se->got_init){
		enum fuse_opcode expected;

		expected = se->cuse_data ? CUSE_INIT : FUSE_INIT;
		if (r_req->in.opcode != expected)
			goto reply_err;
	} else if (r_req->in.opcode == FUSE_INIT || r_req->in.opcode == CUSE_INIT)
		goto reply_err;

	err = EACCES;
	if (se->deny_others && r_req->in.uid != se->owner && r_req->in.uid != 0 &&
		r_req->in.opcode != FUSE_INIT && r_req->in.opcode != FUSE_READ &&
		r_req->in.opcode != FUSE_WRITE && r_req->in.opcode != FUSE_FSYNC &&
		r_req->in.opcode != FUSE_RELEASE && r_req->in.opcode != FUSE_READDIR &&
		r_req->in.opcode != FUSE_FSYNCDIR && r_req->in.opcode != FUSE_RELEASEDIR &&
		r_req->in.opcode != FUSE_NOTIFY_REPLY &&
		r_req->in.opcode != FUSE_READDIRPLUS)
		goto reply_err;
	
	err = ENOSYS;
	if (r_req->in.opcode >= FUSE_MAXOP || !rfuse_ll_ops[r_req->in.opcode].func)
		goto reply_err;

	GET_TIMESTAMPS(3)
	if (r_req->in.opcode == FUSE_WRITE && se->op.write_buf) {
		err = rfuse_prep_write_buf(u_req, se, &w->fbuf, w->ch);
		if(err < 0)
			goto reply_err;
		rfuse_do_write_buf(u_req, r_req->in.nodeid, &w->fbuf);
	} else if (r_req->in.opcode == FUSE_NOTIFY_REPLY) {
		//do_notify_reply(req, r_req->in.nodeid);
	} else {
		rfuse_ll_ops[r_req->in.opcode].func(u_req, r_req->in.nodeid);
	}

	return processed;
reply_err: 
	fuse_reply_err(u_req, err);
out:
	return processed;
}

void *fuse_req_userdata(fuse_req_t req)
{
	return req->se->userdata;
}

const struct fuse_ctx *fuse_req_ctx(fuse_req_t req)
{
	return &req->ctx;
}

#ifdef linux
int fuse_req_getgroups(fuse_req_t req, int size, gid_t list[])
{
	char *buf;
	size_t bufsize = 1024;
	char path[128];
	int ret;
	int fd;
	unsigned long pid = req->ctx.pid;
	char *s;

	sprintf(path, "/proc/%lu/task/%lu/status", pid, pid);

retry:
	buf = malloc(bufsize);
	if (buf == NULL)
		return -ENOMEM;

	ret = -EIO;
	fd = open(path, O_RDONLY);
	if (fd == -1)
		goto out_free;

	ret = read(fd, buf, bufsize);
	close(fd);
	if (ret < 0) {
		ret = -EIO;
		goto out_free;
	}

	if ((size_t)ret == bufsize) {
		free(buf);
		bufsize *= 4;
		goto retry;
	}

	ret = -EIO;
	s = strstr(buf, "\nGroups:");
	if (s == NULL)
		goto out_free;

	s += 8;
	ret = 0;
	while (1) {
		char *end;
		unsigned long val = strtoul(s, &end, 0);
		if (end == s)
			break;

		s = end;
		if (ret < size)
			list[ret] = val;
		ret++;
	}

out_free:
	free(buf);
	return ret;
}
#else /* linux */
/*
 * This is currently not implemented on other than Linux...
 */
int fuse_req_getgroups(fuse_req_t req, int size, gid_t list[])
{
	(void) req; (void) size; (void) list;
	return -ENOSYS;
}
#endif

int fuse_req_interrupted(fuse_req_t req)
{
	int interrupted;

	pthread_mutex_lock(&req->se->lock);
	interrupted = req->interrupted;
	pthread_mutex_unlock(&req->se->lock);

	return interrupted;
}
