#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/statfs.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/exportfs.h>
#include <linux/posix_acl.h>
#include <linux/pid_namespace.h>

/************ 0. Copy of original fuse functions ************/

#define RFUSE_SUPER_MAGIC 0x65735546


static void rfuse_sanitize_global_limit(unsigned *limit)
{
	/*
	 * The default maximum number of async requests is calculated to consume
	 * 1/2^13 of the total memory, assuming 392 bytes per request.
	 */
	if (*limit == 0)
		*limit = ((totalram_pages() << PAGE_SHIFT) >> 13) / 392;

	if (*limit >= 1 << 16)
		*limit = (1 << 16) - 1;
}


static void process_init_limits(struct fuse_conn *fc, struct fuse_init_out *arg)
{
	int cap_sys_admin = capable(CAP_SYS_ADMIN);

	if (arg->minor < 13)
		return;

	rfuse_sanitize_global_limit(&max_user_bgreq);
	rfuse_sanitize_global_limit(&max_user_congthresh);

	spin_lock(&fc->bg_lock);
	if (arg->max_background) {
		fc->max_background = arg->max_background;

		if (!cap_sys_admin && fc->max_background > max_user_bgreq)
			fc->max_background = max_user_bgreq;
	}
	if (arg->congestion_threshold) {
		fc->congestion_threshold = arg->congestion_threshold;

		if (!cap_sys_admin &&
		    fc->congestion_threshold > max_user_congthresh)
			fc->congestion_threshold = max_user_congthresh;
	}
	spin_unlock(&fc->bg_lock);
}

static void convert_rfuse_statfs(struct kstatfs *stbuf, struct fuse_kstatfs *attr)
{
	stbuf->f_type    = RFUSE_SUPER_MAGIC;
	stbuf->f_bsize   = attr->bsize;
	stbuf->f_frsize  = attr->frsize;
	stbuf->f_blocks  = attr->blocks;
	stbuf->f_bfree   = attr->bfree;
	stbuf->f_bavail  = attr->bavail;
	stbuf->f_files   = attr->files;
	stbuf->f_ffree   = attr->ffree;
	stbuf->f_namelen = attr->namelen;
	/* fsid is left zero */
}



/************ 1. INIT ************/

static void rfuse_process_init_reply(struct fuse_mount *fm, struct rfuse_req *r_req, int error){
	struct fuse_conn *fc = fm->fc;

	struct fuse_init_out *arg = (struct fuse_init_out *)((char*)&r_req->args + sizeof(struct fuse_init_in)); 
	bool ok = true;

	printk("RFUSE: rfuse_process_init_reply Start\n");
	if (error || arg->major != FUSE_KERNEL_VERSION)
		ok = false;
	else {
		unsigned long ra_pages;

		process_init_limits(fc, arg);

		if (arg->minor >= 6) {
			ra_pages = arg->max_readahead / PAGE_SIZE;
			if (arg->flags & FUSE_ASYNC_READ)
				fc->async_read = 1;
			if (!(arg->flags & FUSE_POSIX_LOCKS))
				fc->no_lock = 1;
			if (arg->minor >= 17) {
				if (!(arg->flags & FUSE_FLOCK_LOCKS))
					fc->no_flock = 1;
			} else {
				if (!(arg->flags & FUSE_POSIX_LOCKS))
					fc->no_flock = 1;
			}
			if (arg->flags & FUSE_ATOMIC_O_TRUNC)
				fc->atomic_o_trunc = 1;
			if (arg->minor >= 9) {
				/* LOOKUP has dependency on proto version */
				if (arg->flags & FUSE_EXPORT_SUPPORT)
					fc->export_support = 1;
			}
			if (arg->flags & FUSE_BIG_WRITES)
				fc->big_writes = 1;
			if (arg->flags & FUSE_DONT_MASK)
				fc->dont_mask = 1;
			if (arg->flags & FUSE_AUTO_INVAL_DATA)
				fc->auto_inval_data = 1;
			else if (arg->flags & FUSE_EXPLICIT_INVAL_DATA)
				fc->explicit_inval_data = 1;
			if (arg->flags & FUSE_DO_READDIRPLUS) {
				fc->do_readdirplus = 1;
				if (arg->flags & FUSE_READDIRPLUS_AUTO)
					fc->readdirplus_auto = 1;
			}
			if (arg->flags & FUSE_ASYNC_DIO)
				fc->async_dio = 1;
			if (arg->flags & FUSE_WRITEBACK_CACHE)
				fc->writeback_cache = 1;
			if (arg->flags & FUSE_PARALLEL_DIROPS)
				fc->parallel_dirops = 1;
			if (arg->flags & FUSE_HANDLE_KILLPRIV)
				fc->handle_killpriv = 1;
			if (arg->time_gran && arg->time_gran <= 1000000000)
				fm->sb->s_time_gran = arg->time_gran;
			if ((arg->flags & FUSE_POSIX_ACL)) {
				fc->default_permissions = 1;
				fc->posix_acl = 1;
				fm->sb->s_xattr = fuse_acl_xattr_handlers;
			}
			if (arg->flags & FUSE_CACHE_SYMLINKS)
				fc->cache_symlinks = 1;
			if (arg->flags & FUSE_ABORT_ERROR)
				fc->abort_err = 1;
			if (arg->flags & FUSE_MAX_PAGES) {
				fc->max_pages =
					min_t(unsigned int, fc->max_pages_limit,
					max_t(unsigned int, arg->max_pages, 1));
			}
			if (IS_ENABLED(CONFIG_FUSE_DAX) &&
			    arg->flags & FUSE_MAP_ALIGNMENT &&
			    !fuse_dax_check_alignment(fc, arg->map_alignment)) {
				ok = false;
			}
			if (arg->flags & FUSE_HANDLE_KILLPRIV_V2) {
				fc->handle_killpriv_v2 = 1;
				fm->sb->s_flags |= SB_NOSEC;
			}
			if (arg->flags & FUSE_SETXATTR_EXT)
				fc->setxattr_ext = 1;
		} else {
			ra_pages = fc->max_read / PAGE_SIZE;
			fc->no_lock = 1;
			fc->no_flock = 1;
		}

		fm->sb->s_bdi->ra_pages =
				min(fm->sb->s_bdi->ra_pages, ra_pages);
		fc->minor = arg->minor;
		fc->max_write = arg->minor < 5 ? 4096 : arg->max_write;
		fc->max_write = max_t(unsigned, 4096, fc->max_write);
		fc->conn_init = 1;
	}

	if (!ok) {
		printk("It's not okay\n");
		fc->conn_init = 0;
		fc->conn_error = 1;
	}
	fuse_set_initialized(fc);
	wake_up_all(&fc->blocked_waitq);
	printk("RFUSE: rfuse_process_init_reply End\n");
}

void rfuse_send_init(struct fuse_mount *fm){
	struct rfuse_req *r_req;
	struct fuse_init_in *inarg;

	r_req = rfuse_get_req(fm, true, true);
	inarg = (struct fuse_init_in*)&r_req->args;

	inarg->major = FUSE_KERNEL_VERSION;
	inarg->minor = FUSE_KERNEL_MINOR_VERSION;
	inarg->max_readahead = fm->sb->s_bdi->ra_pages * PAGE_SIZE;
	inarg->flags |=
		FUSE_ASYNC_READ | FUSE_POSIX_LOCKS | FUSE_ATOMIC_O_TRUNC |
		FUSE_EXPORT_SUPPORT | FUSE_BIG_WRITES | FUSE_DONT_MASK |
		FUSE_SPLICE_WRITE | FUSE_SPLICE_MOVE | FUSE_SPLICE_READ |
		FUSE_FLOCK_LOCKS | FUSE_HAS_IOCTL_DIR | FUSE_AUTO_INVAL_DATA |
		FUSE_DO_READDIRPLUS | FUSE_READDIRPLUS_AUTO | FUSE_ASYNC_DIO |
		FUSE_WRITEBACK_CACHE | FUSE_NO_OPEN_SUPPORT |
		FUSE_PARALLEL_DIROPS | FUSE_HANDLE_KILLPRIV | FUSE_POSIX_ACL |
		FUSE_ABORT_ERROR | FUSE_MAX_PAGES | FUSE_CACHE_SYMLINKS |
		FUSE_NO_OPENDIR_SUPPORT | FUSE_EXPLICIT_INVAL_DATA |
		FUSE_HANDLE_KILLPRIV_V2 | FUSE_SETXATTR_EXT;
#ifdef CONFIG_FUSE_DAX
	if (fm->fc->dax)
		inarg->flags |= FUSE_MAP_ALIGNMENT;
#endif
	if (fm->fc->auto_submounts)
		inarg->flags |= FUSE_SUBMOUNTS;

	r_req->in.opcode = FUSE_INIT;
	__set_bit(FR_BACKGROUND,&r_req->flags);
	__set_bit(FR_ASYNC,&r_req->flags);
	r_req->end = rfuse_process_init_reply;

	if(rfuse_simple_background(fm, r_req) != 0){
		printk("RFUSE: rfuse_send_init: rfuse_simple_background failed\n");
		rfuse_process_init_reply(fm, r_req, -ENOTCONN);
	}

}



/************ 2. STATFS  ************/

int rfuse_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct fuse_mount *fm = get_fuse_mount_super(sb);
	struct rfuse_req *r_req;
	struct fuse_statfs_out *outarg;

	int err;

	if (!fuse_allow_current_process(fm->fc)) {
		buf->f_type = RFUSE_SUPER_MAGIC;
		return 0;
	}

	r_req = rfuse_get_req(fm, false, false);
	outarg = (struct fuse_statfs_out*)&r_req->args;

	r_req->in.opcode = FUSE_STATFS;
	r_req->in.nodeid = get_node_id(d_inode(dentry));
	err = rfuse_simple_request(r_req);

	if(!err)
		convert_rfuse_statfs(buf,&outarg->st);
	
	rfuse_put_request(r_req);
	return err;
}


/************ 3. DESTROY  ************/

void rfuse_send_destroy(struct fuse_mount *fm)
{
	if (fm->fc->conn_init) {
		struct rfuse_req *r_req;
		r_req = rfuse_get_req(fm, false, true);
		r_req->in.opcode = FUSE_DESTROY;
		r_req->force = true;
		r_req->nocreds = true;
		rfuse_simple_request(r_req);
	}
}
