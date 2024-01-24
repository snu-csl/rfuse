#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/module.h>
#include <linux/swap.h>
#include <linux/falloc.h>
#include <linux/uio.h>
#include <linux/fs.h>

struct rfuse_release_in {
	struct fuse_release_in inarg;
	struct inode *inode;
};


/************ 0. Copy of original fuse functions ************/

/*
 * Wait for all pending writepages on the inode to finish.
 *
 * This is currently done by blocking further writes with FUSE_NOWRITE
 * and waiting for all sent writes to complete.
 *
 * This must be called under i_mutex, otherwise the FUSE_NOWRITE usage
 * could conflict with truncation.
 */
static void rfuse_sync_writes(struct inode *inode)
{
	fuse_set_nowrite(inode);
	fuse_release_nowrite(inode);
}

static unsigned int rfuse_write_flags(struct kiocb *iocb)
{
	unsigned int flags = iocb->ki_filp->f_flags;

	if (iocb->ki_flags & IOCB_DSYNC)
		flags |= O_DSYNC;
	if (iocb->ki_flags & IOCB_SYNC)
		flags |= O_SYNC;

	return flags;
}

static inline unsigned int rfuse_wr_pages(loff_t pos, size_t len,
				     unsigned int max_pages)
{
	return min_t(unsigned int,
		     ((pos + len - 1) >> PAGE_SHIFT) -
		     (pos >> PAGE_SHIFT) + 1,
		     max_pages);
}

static void rfuse_read_update_size(struct inode *inode, loff_t size,
				  u64 attr_ver)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);

	spin_lock(&fi->lock);
	if (attr_ver == fi->attr_version && size < inode->i_size &&
	    !test_bit(FUSE_I_SIZE_UNSTABLE, &fi->state)) {
		fi->attr_version = atomic64_inc_return(&fc->attr_version);
		i_size_write(inode, size);
	}
	spin_unlock(&fi->lock);
}

static struct fuse_file *rfuse_file_get(struct fuse_file *ff)
{
	refcount_inc(&ff->count);
	return ff;
}


/************ 1. FLUSH ************/

int rfuse_flush(struct file *file, fl_owner_t id)
{
	struct inode *inode = file_inode(file);
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_flush_in *inarg;
    struct rfuse_req *r_req;

	int err;

	if (fuse_is_bad(inode))
		return -EIO;

	err = write_inode_now(inode, 1);
	if (err)
		return err;

	inode_lock(inode);
	rfuse_sync_writes(inode);
	inode_unlock(inode);

	err = filemap_check_errors(file->f_mapping);
	if (err)
		return err;

	err = 0;
	if (fm->fc->no_flush)
		goto inval_attr_out;

    r_req = rfuse_get_req(fm, false, true);
    inarg = (struct fuse_flush_in*)&r_req->args;

	inarg->fh = ff->fh;
	inarg->lock_owner = fuse_lock_owner_id(fm->fc, id);
	
    r_req->in.opcode = FUSE_FLUSH;
    r_req->in.nodeid = get_node_id(inode);

	err = rfuse_simple_request(r_req);
	if (err == -ENOSYS) {
		fm->fc->no_flush = 1;
		err = 0;
	}
    rfuse_put_request(r_req); 
inval_attr_out:
	/*
	 * In memory i_blocks is not maintained by fuse, if writeback cache is
	 * enabled, i_blocks from cached attr may not be accurate.
	 */
	if (!err && fm->fc->writeback_cache)
		fuse_invalidate_attr(inode);
	return err;
}


/************ 2. FSYNC ************/

int rfuse_fsync_common(struct file *file, loff_t start, loff_t end,
		      int datasync, int opcode)
{
	struct inode *inode = file->f_mapping->host;
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct fuse_file *ff = file->private_data;
	struct rfuse_req *r_req;
	struct fuse_fsync_in *inarg;
	int err;

	r_req = rfuse_get_req(fm, false, false);
	inarg = (struct fuse_fsync_in*)&r_req->args;

	inarg->fh = ff->fh;
	inarg->fsync_flags = datasync ? FUSE_FSYNC_FDATASYNC : 0;
	
	r_req->in.opcode = opcode;
	r_req->in.nodeid = get_node_id(inode);

	err = rfuse_simple_request(r_req);
	rfuse_put_request(r_req); 
	
	return err;
}

int rfuse_fsync(struct file *file, loff_t start, loff_t end,
		      int datasync){
	struct inode *inode = file->f_mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	int err;

	if (fuse_is_bad(inode))
		return -EIO;

	inode_lock(inode);

	/*
	 * Start writeback against all dirty pages of the inode, then
	 * wait for all outstanding writes, before sending the FSYNC
	 * request.
	 */
	err = file_write_and_wait_range(file, start, end);
	if (err)
		goto out;

	rfuse_sync_writes(inode);

	/*
	 * Due to implementation of fuse writeback
	 * file_write_and_wait_range() does not catch errors.
	 * We have to do this directly after fuse_sync_writes()
	 */
	err = file_check_and_advance_wb_err(file);
	if (err)
		goto out;

	err = sync_inode_metadata(inode, 1);
	if (err)
		goto out;

	if (fc->no_fsync)
		goto out;

	err = rfuse_fsync_common(file, start, end, datasync, FUSE_FSYNC);
	if (err == -ENOSYS) {
		fc->no_fsync = 1;
		err = 0;
	}
out:
	inode_unlock(inode);

	return err;
}

/************ 2. OPEN, OPENDIR ************/

static int rfuse_send_open(struct fuse_mount *fm, u64 nodeid,
			  unsigned int open_flags, int opcode,
			  struct rfuse_req *r_req){
	struct fuse_open_in *inarg = (struct fuse_open_in*)&r_req->args;

	inarg->flags = open_flags & ~(O_CREAT | O_EXCL | O_NOCTTY);
	if (!fm->fc->atomic_o_trunc)
		inarg->flags &= ~O_TRUNC;

	if (fm->fc->handle_killpriv_v2 &&
	    (inarg->flags & O_TRUNC) && !capable(CAP_FSETID)) {
		inarg->open_flags |= FUSE_OPEN_KILL_SUIDGID;
	}

	r_req->in.opcode = opcode;
	r_req->in.nodeid = nodeid;

	return rfuse_simple_request(r_req);
}


struct fuse_file *rfuse_file_open(struct fuse_mount *fm, u64 nodeid,
				 unsigned int open_flags, bool isdir)
{
	struct fuse_conn *fc = fm->fc;
	struct fuse_file *ff;
	int opcode = isdir ? FUSE_OPENDIR : FUSE_OPEN;

	ff = fuse_file_alloc(fm);
	if (!ff)
		return ERR_PTR(-ENOMEM);

	ff->fh = 0;
	/* Default for no-open */
	ff->open_flags = FOPEN_KEEP_CACHE | (isdir ? FOPEN_CACHE_DIR : 0);
	if (isdir ? !fc->no_opendir : !fc->no_open) {
    		struct rfuse_req *r_req;
		struct fuse_open_out *outarg;
		int err;

		r_req = rfuse_get_req(fm, false, false);

		err = rfuse_send_open(fm, nodeid, open_flags, opcode, r_req);
		outarg = (struct fuse_open_out*)&r_req->args;
	
		if (!err) {
			ff->fh = outarg->fh;
			ff->open_flags = outarg->open_flags;
		} else if (err != -ENOSYS) {
			fuse_file_free(ff);
			rfuse_put_request(r_req); 
			return ERR_PTR(err);
		} else {
			if (isdir)
				fc->no_opendir = 1;
			else
				fc->no_open = 1;
		}
		rfuse_put_request(r_req); 
	}

	if (isdir)
		ff->open_flags &= ~FOPEN_DIRECT_IO;

	ff->nodeid = nodeid;

	return ff;
}


/************ 2. RELEASE, RELEASEDIR ************/

static void rfuse_release_end(struct fuse_mount *fm, struct rfuse_req *r_req, int error){
	struct rfuse_release_in *rfuse_inarg = (struct rfuse_release_in*)&r_req->args;
	iput(rfuse_inarg->inode);
}

static void rfuse_file_put(struct fuse_file *ff, struct rfuse_req *r_req,
				 bool sync, bool isdir){
	if (refcount_dec_and_test(&ff->count)) {
		if(!r_req || isdir ? r_req->in.opcode != FUSE_RELEASEDIR : r_req->in.opcode != FUSE_RELEASE) {
			struct rfuse_req *new_r_req;
			struct rfuse_release_in *new_rfuse_inarg;
			
			if(sync)
				new_r_req = rfuse_get_req(ff->fm, false, true);
			else
				new_r_req = rfuse_get_req(ff->fm, true, true);

			new_rfuse_inarg = (struct rfuse_release_in*)&new_r_req->args;

			new_rfuse_inarg->inarg = ff->release_args->inarg;
			new_rfuse_inarg->inode = ff->release_args->inode;

			new_r_req->in.opcode = ff->release_args->args.opcode;
			new_r_req->in.nodeid = ff->release_args->args.nodeid;

			if (isdir ? ff->fm->fc->no_opendir : ff->fm->fc->no_open) {
				/* Do nothing when client does not implement 'open' */
				rfuse_release_end(ff->fm, new_r_req, 0);
			} else if (sync) {
				rfuse_simple_request(new_r_req);
				rfuse_release_end(ff->fm, new_r_req, 0);
				rfuse_put_request(new_r_req);
			} else {
				new_r_req->end = rfuse_release_end;
				if (rfuse_simple_background(ff->fm, new_r_req))
					rfuse_release_end(ff->fm, new_r_req, -ENOTCONN);
			}
		} else {
			if (isdir ? ff->fm->fc->no_opendir : ff->fm->fc->no_open) {
				/* Do nothing when client does not implement 'open' */
				rfuse_release_end(ff->fm, r_req, 0);
			} else if (sync) {
				rfuse_simple_request(r_req);
				rfuse_release_end(ff->fm, r_req, 0);
			} else {
				r_req->end = rfuse_release_end;
				if (rfuse_simple_background(ff->fm, r_req))
					rfuse_release_end(ff->fm, r_req, -ENOTCONN);
			}
		}

		kfree(ff);
	}
}

static void rfuse_prepare_release(struct fuse_inode *fi, struct fuse_file *ff,
				 struct rfuse_req *r_req, unsigned int flags, int opcode){
	
	struct fuse_conn *fc = ff->fm->fc;
	struct rfuse_release_in *rfuse_inarg = (struct rfuse_release_in*)&r_req->args;

	/* Inode is NULL on error path of fuse_create_open() */
	if (likely(fi)) {
		spin_lock(&fi->lock);
		list_del(&ff->write_entry);
		spin_unlock(&fi->lock);
	}
	spin_lock(&fc->lock);
	if (!RB_EMPTY_NODE(&ff->polled_node))
		rb_erase(&ff->polled_node, &fc->polled_files);
	spin_unlock(&fc->lock);

	wake_up_interruptible_all(&ff->poll_wait);

	rfuse_inarg->inarg.fh = ff->fh;
	rfuse_inarg->inarg.flags = flags;
	r_req->in.opcode = opcode;
	r_req->in.nodeid = ff->nodeid;
}

void rfuse_sync_release(struct fuse_inode *fi, struct fuse_file *ff,
		       unsigned int flags){
	struct rfuse_req *r_req;
	struct fuse_mount *fm = ff->fm;

	WARN_ON(refcount_read(&ff->count) > 1);
	r_req = rfuse_get_req(fm, false, true);
	rfuse_prepare_release(fi, ff, r_req, flags, FUSE_RELEASE);
	/*
	 * iput(NULL) is a no-op and since the refcount is 1 and everything's
	 * synchronous, we are fine with not doing igrab() here"
	 */
	rfuse_file_put(ff, r_req, true, false);
	rfuse_put_request(r_req);
}

void rfuse_file_release(struct inode *inode, struct fuse_file *ff,
		       unsigned int open_flags, fl_owner_t id, bool isdir){

	struct fuse_inode *fi = get_fuse_inode(inode);
	int opcode = isdir ? FUSE_RELEASEDIR : FUSE_RELEASE;
	struct rfuse_req *r_req;
	struct rfuse_release_in *rfuse_inarg;  
	struct fuse_mount *fm = ff->fm;
	struct fuse_release_args *ra = ff->release_args;

	if(ff->fm->fc->destroy)
		r_req = rfuse_get_req(fm, false, true);
	else
		r_req = rfuse_get_req(fm, true, true);
	
	rfuse_prepare_release(fi, ff, r_req, open_flags, opcode);
	rfuse_inarg = (struct rfuse_release_in*)&r_req->args;

	if (ff->flock) {
		rfuse_inarg->inarg.release_flags |= FUSE_RELEASE_FLOCK_UNLOCK;
		rfuse_inarg->inarg.lock_owner = fuse_lock_owner_id(ff->fm->fc, id);
	}
	/* Hold inode until release is finished */
	rfuse_inarg->inode = igrab(inode);

	/*
	 * Normally this will send the RELEASE request, however if
	 * some asynchronous READ or WRITE requests are outstanding,
	 * the sending will be delayed.
	 */
	ra->inarg.fh = ff->fh;
	ra->inarg.flags = open_flags;
	ra->args.opcode = opcode;
	ra->args.nodeid = ff->nodeid;
	ra->inode = inode;


	rfuse_file_put(ff, r_req, ff->fm->fc->destroy, isdir);
	if(ff->fm->fc->destroy) // Only put requests that are synchronous
		rfuse_put_request(r_req);
}


/************ 3. DIRECT IO ************/

static struct rfuse_io_args *rfuse_io_alloc(struct fuse_io_priv *io, unsigned int npages);
static void rfuse_io_free(struct rfuse_io_args *ria);
static ssize_t rfuse_send_write(struct rfuse_io_args *ria, loff_t pos, size_t count, fl_owner_t owner);
static ssize_t rfuse_send_read(struct rfuse_io_args *ria, loff_t pos, size_t count, fl_owner_t owner);
static ssize_t __rfuse_direct_read(struct fuse_io_priv *io, struct iov_iter *iter, loff_t *ppos);

static inline loff_t rfuse_round_up(struct fuse_conn *fc, loff_t off)
{
	return round_up(off, fc->max_pages << PAGE_SHIFT);
}

struct rfuse_writepage_args {
	struct rfuse_io_args ria;
	struct rb_node writepages_entry;
	struct list_head queue_entry;
	struct rfuse_writepage_args *next;
	struct inode *inode;
	struct fuse_sync_bucket *bucket;
	loff_t pos;
};

static struct rfuse_writepage_args *rfuse_find_writeback(struct fuse_inode *fi,
					    pgoff_t idx_from, pgoff_t idx_to)
{
	struct rb_node *n;

	n = fi->writepages.rb_node;

	while (n) {
		struct rfuse_writepage_args *r_wpa;
		pgoff_t curr_index;

		r_wpa = rb_entry(n, struct rfuse_writepage_args, writepages_entry);
		WARN_ON(get_fuse_inode(r_wpa->inode) != fi);
		curr_index = r_wpa->ria.write.in.offset >> PAGE_SHIFT;
		if (idx_from >= curr_index + r_wpa->ria.rp.num_pages)
			n = n->rb_right;
		else if (idx_to < curr_index)
			n = n->rb_left;
		else
			return r_wpa;
	}
	return NULL;
}

static bool rfuse_range_is_writeback(struct inode *inode, pgoff_t idx_from,
				   pgoff_t idx_to)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	bool found;

	spin_lock(&fi->lock);
	found = rfuse_find_writeback(fi, idx_from, idx_to);
	spin_unlock(&fi->lock);

	return found;
}

static inline bool rfuse_page_is_writeback(struct inode *inode, pgoff_t index)
{
	return rfuse_range_is_writeback(inode, index, index);
}

void rfuse_wait_on_page_writeback(struct inode *inode, pgoff_t index)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	wait_event(fi->page_waitq, !rfuse_page_is_writeback(inode, index));
}

static void rfuse_do_truncate(struct file *file)
{
	struct inode *inode = file->f_mapping->host;
	struct iattr attr;

	attr.ia_valid = ATTR_SIZE;
	attr.ia_size = i_size_read(inode);

	attr.ia_file = file;
	attr.ia_valid |= ATTR_FILE;

	fuse_do_setattr(file_dentry(file), &attr, file);
}

static void rfuse_io_release(struct kref *kref)
{
	kfree(container_of(kref, struct fuse_io_priv, refcnt));
}

static ssize_t rfuse_get_res_by_io(struct fuse_io_priv *io)
{
	if (io->err)
		return io->err;

	if (io->bytes >= 0 && io->write)
		return -EIO;

	return io->bytes < 0 ? io->size : io->bytes;
}

static void rfuse_aio_complete(struct fuse_io_priv *io, int err, ssize_t pos)
{
	int left;
	ssize_t res;

	spin_lock(&io->lock);
	if (err)
		io->err = io->err ? : err;
	else if (pos >= 0 && (io->bytes < 0 || pos < io->bytes))
		io->bytes = pos;

	left = --io->reqs;
	if (!left && io->blocking)
		complete(io->done);
	spin_unlock(&io->lock);

	if (!left && !io->blocking) {
		printk("io is non blocking\n");
		res = rfuse_get_res_by_io(io);

		if (res >= 0) {
			struct inode *inode = file_inode(io->iocb->ki_filp);
			struct fuse_conn *fc = get_fuse_conn(inode);
			struct fuse_inode *fi = get_fuse_inode(inode);

			spin_lock(&fi->lock);
			fi->attr_version = atomic64_inc_return(&fc->attr_version);
			spin_unlock(&fi->lock);
		}

		io->iocb->ki_complete(io->iocb, res, 0);
	}

	kref_put(&io->refcnt, rfuse_io_release);
}

static int rfuse_get_user_pages(struct rfuse_io_args *ria, struct iov_iter *ii,
			       size_t *nbytesp, int write,
			       unsigned int max_pages)
{
	size_t nbytes = 0;  /* # bytes already packed in req */
	ssize_t ret = 0;
	struct rfuse_pages *rp = &ria->rp;

	/* Special case for kernel I/O: can copy directly into the buffer */
	if (iov_iter_is_kvec(ii)) {
		printk("iov_iter_is_kvec = true\n");
		/*
		unsigned long user_addr = fuse_get_user_addr(ii);
		size_t frag_size = fuse_get_frag_size(ii, *nbytesp);

		if (write)
			ap->args.in_args[1].value = (void *) user_addr;
		else
			ap->args.out_args[0].value = (void *) user_addr;

		iov_iter_advance(ii, frag_size);
		*nbytesp = frag_size;
		return 0;
		*/
	}

	printk("rfuse_get_uesr_pages: nbytesp : %ld, max_pages: %d\n", *nbytesp, max_pages);
	while (nbytes < *nbytesp && rp->num_pages < max_pages) {
		unsigned npages;
		size_t start;
		printk("rfuse_get_user_pages: while start\n");
		ret = iov_iter_get_pages(ii, &rp->pages[rp->num_pages],
					*nbytesp - nbytes,
					max_pages - rp->num_pages,
					&start);
		if (ret < 0)
			break;

		iov_iter_advance(ii, ret);
		nbytes += ret;

		ret += start;
		npages = DIV_ROUND_UP(ret, PAGE_SIZE);

		rp->descs[rp->num_pages].offset = start;
		fuse_page_descs_length_init(rp->descs, rp->num_pages, npages);

		rp->num_pages += npages;
		rp->descs[rp->num_pages - 1].length -=
			(PAGE_SIZE - ret) & (PAGE_SIZE - 1);
	}

	*nbytesp = nbytes;

	return ret < 0 ? ret : 0;
}

static void rfuse_release_user_pages(struct rfuse_pages *rp,
				    bool should_dirty)
{
	unsigned int i;

	for (i = 0; i < rp->num_pages; i++) {
		if (should_dirty)
			set_page_dirty_lock(rp->pages[i]);
		put_page(rp->pages[i]);
	}
}

static void rfuse_aio_complete_req(struct fuse_mount *fm, struct rfuse_req *r_req,
				  int err)
{
	struct rfuse_pages *rp = r_req->rp;
	struct rfuse_io_args *ria = container_of(rp, typeof(*ria),rp);
	struct fuse_io_priv *io = ria->io;
	ssize_t pos = -1;

	rfuse_release_user_pages(r_req->rp, io->should_dirty);

	if (err) {
		/* Nothing */
	} else if (io->write) {
		/* For this code lines, revoke fuse_write_out in rfuse_io_args.write and initialize it in rfuse_write_args_fill*/
		struct fuse_write_out *outarg = (struct fuse_write_out *)&r_req->args;
		if (outarg->size > ria->write.in.size) {
			err = -EIO;
		} else if (ria->write.in.size != outarg->size) {
			pos = ria->write.in.offset - io->offset +
				outarg->size;
		}
	} else {
		u32 outsize = r_req->out.arglen;
		struct fuse_read_in *inarg = (struct fuse_read_in *)&r_req->args;

		if (inarg->size != outsize)
			pos = inarg->offset - io->offset + outsize;
	}

	rfuse_aio_complete(io, err, pos);
	rfuse_io_free(ria);
}

ssize_t rfuse_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	DECLARE_COMPLETION_ONSTACK(wait);
	ssize_t ret = 0;
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	loff_t pos = 0;
	struct inode *inode;
	loff_t i_size;
	size_t count = iov_iter_count(iter), shortened = 0;
	loff_t offset = iocb->ki_pos;
	struct fuse_io_priv *io;

	pos = offset;
	inode = file->f_mapping->host;
	i_size = i_size_read(inode);

	if ((iov_iter_rw(iter) == READ) && (offset >= i_size))
		return 0;

	io = kmalloc(sizeof(struct fuse_io_priv), GFP_KERNEL);
	if (!io)
		return -ENOMEM;
	spin_lock_init(&io->lock);
	kref_init(&io->refcnt);
	io->reqs = 1;
	io->bytes = -1;
	io->size = 0;
	io->offset = offset;
	io->write = (iov_iter_rw(iter) == WRITE);
	io->err = 0;
	/*
	 * By default, we want to optimize all I/Os with async request
	 * submission to the client filesystem if supported.
	 */
	io->async = ff->fm->fc->async_dio;
	io->iocb = iocb;
	io->blocking = is_sync_kiocb(iocb);

	/* optimization for short read */
	if (io->async && !io->write && offset + count > i_size) {
		iov_iter_truncate(iter, rfuse_round_up(ff->fm->fc, i_size - offset));
		shortened = count - iov_iter_count(iter);
		count -= shortened;
	}

	/*
	 * We cannot asynchronously extend the size of a file.
	 * In such case the aio will behave exactly like sync io.
	 */
	if ((offset + count > i_size) && io->write)
		io->blocking = true;

	if (io->async && io->blocking) {
		/*
		 * Additional reference to keep io around after
		 * calling fuse_aio_complete()
		 */
		kref_get(&io->refcnt);
		io->done = &wait;
	}

	if (iov_iter_rw(iter) == WRITE) {
		ret = rfuse_direct_io(io, iter, &pos, FUSE_DIO_WRITE);
		fuse_invalidate_attr(inode);
	} else {
		ret = __rfuse_direct_read(io, iter, &pos);
	}
	iov_iter_reexpand(iter, iov_iter_count(iter) + shortened);

	if (io->async) {
		bool blocking = io->blocking;

		rfuse_aio_complete(io, ret < 0 ? ret : 0, -1);

		/* we have a non-extending, async request, so return */
		if (!blocking)
			return -EIOCBQUEUED;

		printk("direct_IO: wait is started\n");
		wait_for_completion(&wait);
		printk("direct_IO: wait is ended\n");
		ret = rfuse_get_res_by_io(io);
	}

	kref_put(&io->refcnt, rfuse_io_release);

	if (iov_iter_rw(iter) == WRITE) {
		if (ret > 0)
			fuse_write_update_size(inode, pos);
		else if (ret < 0 && offset + count > i_size)
			rfuse_do_truncate(file);
	}

	return ret;
}

ssize_t rfuse_direct_io(struct fuse_io_priv *io, struct iov_iter *iter,
		       loff_t *ppos, int flags)
{
	int write = flags & FUSE_DIO_WRITE;
	int cuse = flags & FUSE_DIO_CUSE;
	struct file *file = io->iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fm->fc;
	size_t nmax = write ? fc->max_write : fc->max_read;
	loff_t pos = *ppos;
	size_t count = iov_iter_count(iter);
	pgoff_t idx_from = pos >> PAGE_SHIFT;
	pgoff_t idx_to = (pos + count - 1) >> PAGE_SHIFT;
	ssize_t res = 0;
	int err = 0;
	struct rfuse_io_args *ria;
	unsigned int max_pages;

	max_pages = iov_iter_npages(iter, fc->max_pages);
	ria = rfuse_io_alloc(io, max_pages);
	if (!ria)
		return -ENOMEM;

	ria->io = io;
	if (!cuse && rfuse_range_is_writeback(inode, idx_from, idx_to)) {
		if (!write)
			inode_lock(inode);
		rfuse_sync_writes(inode);
		if (!write)
			inode_unlock(inode);
	}

	io->should_dirty = !write && iter_is_iovec(iter);
	while (count) {
		ssize_t nres;
		fl_owner_t owner = current->files;
		size_t nbytes = min(count, nmax);

		err = rfuse_get_user_pages(ria, iter, &nbytes, write,
					  max_pages);
		if (err && !nbytes)
			break;

		if (write) {
			nres = rfuse_send_write(ria, pos, nbytes, owner);
		} else {
			nres = rfuse_send_read(ria, pos, nbytes, owner);
		}

		if (!io->async || nres < 0) {
			rfuse_release_user_pages(&ria->rp, io->should_dirty);
			rfuse_io_free(ria);
		}
		ria = NULL;
		if (nres < 0) {
			iov_iter_revert(iter, nbytes);
			err = nres;
			break;
		}
		WARN_ON(nres > nbytes);

		count -= nres;
		res += nres;
		pos += nres;
		if (nres != nbytes) {
			iov_iter_revert(iter, nbytes - nres);
			break;
		}
		if (count) {
			max_pages = iov_iter_npages(iter, fc->max_pages);
			ria = rfuse_io_alloc(io, max_pages);
			if (!ria)
				break;
		}
	}
	if (ria)
		rfuse_io_free(ria);
	if (res > 0)
		*ppos = pos;

	return res > 0 ? res : err;
}
EXPORT_SYMBOL_GPL(rfuse_direct_io);

ssize_t rfuse_direct_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct fuse_io_priv io = FUSE_IO_PRIV_SYNC(iocb);
	ssize_t res;

	/* Don't allow parallel writes to the same file */
	inode_lock(inode);
	res = generic_write_checks(iocb, from);
	if (res > 0) {
		if (!is_sync_kiocb(iocb) && iocb->ki_flags & IOCB_DIRECT) {
			res = rfuse_direct_IO(iocb, from);
		} else {
			res = rfuse_direct_io(&io, from, &iocb->ki_pos,
					     FUSE_DIO_WRITE);
		}
	}
	fuse_invalidate_attr(inode);
	if (res > 0)
		fuse_write_update_size(inode, iocb->ki_pos);
	inode_unlock(inode);

	return res;
}

ssize_t rfuse_direct_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	ssize_t res;

	if (!is_sync_kiocb(iocb) && iocb->ki_flags & IOCB_DIRECT) {
		res = rfuse_direct_IO(iocb, to);
	} else {
		struct fuse_io_priv io = FUSE_IO_PRIV_SYNC(iocb);

		res = __rfuse_direct_read(&io, to, &iocb->ki_pos);
	}

	return res;
}

static ssize_t __rfuse_direct_read(struct fuse_io_priv *io,
				  struct iov_iter *iter,
				  loff_t *ppos)
{
	ssize_t res;
	struct inode *inode = file_inode(io->iocb->ki_filp);

	res = rfuse_direct_io(io, iter, ppos, 0);

	fuse_invalidate_atime(inode);

	return res;
}

static ssize_t rfuse_async_req_send(struct fuse_mount *fm,
				   struct rfuse_io_args *ria, size_t num_bytes)
{
	ssize_t err;
	struct fuse_io_priv *io = ria->io;

	spin_lock(&io->lock);
	kref_get(&io->refcnt);
	io->size += num_bytes;
	io->reqs++;
	spin_unlock(&io->lock);

	ria->r_req->end = rfuse_aio_complete_req;
	ria->r_req->may_block = io->should_dirty;
	err = rfuse_simple_background(fm, ria->r_req);
	if (err) {
		rfuse_aio_complete_req(fm, ria->r_req, err);
	}
	return num_bytes;
}

/************ 4. WRITE ************/


static ssize_t rfuse_fill_write_pages(struct rfuse_io_args *ria, struct address_space *mapping,
				     struct iov_iter *ii, loff_t pos, unsigned int max_pages)
{
	struct rfuse_pages *rp = &ria->rp;
	struct fuse_conn *fc = get_fuse_conn(mapping->host);
	unsigned offset = pos & (PAGE_SIZE - 1);
	size_t count = 0;
	int err;

	ria->r_req->in_pages = true;
	rp->descs[0].offset = offset;

	do {
		size_t tmp;
		struct page *page;
		pgoff_t index = pos >> PAGE_SHIFT;
		size_t bytes = min_t(size_t, PAGE_SIZE - offset,
				     iov_iter_count(ii));

		bytes = min_t(size_t, bytes, fc->max_write - count);

 again:
		err = -EFAULT;
		if (iov_iter_fault_in_readable(ii, bytes))
			break;

		err = -ENOMEM;
		page = grab_cache_page_write_begin(mapping, index, 0);
		if (!page)
			break;

		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		tmp = copy_page_from_iter_atomic(page, offset, bytes, ii);
		flush_dcache_page(page);

		if (!tmp) {
			unlock_page(page);
			put_page(page);
			goto again;
		}

		err = 0;
		rp->pages[rp->num_pages] = page;
		rp->descs[rp->num_pages].length = tmp;
		rp->num_pages++;

		count += tmp;
		pos += tmp;
		offset += tmp;
		if (offset == PAGE_SIZE)
			offset = 0;

		/* If we copied full page, mark it uptodate */
		if (tmp == PAGE_SIZE)
			SetPageUptodate(page);

		if (PageUptodate(page)) {
			unlock_page(page);
		} else {
			ria->write.page_locked = true;
			break;
		}
		if (!fc->big_writes)
			break;
	} while (iov_iter_count(ii) && count < fc->max_write &&
		 rp->num_pages < max_pages && offset == 0);

	return count > 0 ? count : err;
}

static void rfuse_write_args_fill(struct rfuse_io_args *ria, struct fuse_file *ff,
				 loff_t pos, size_t count)
{
	struct rfuse_req *r_req = ria->r_req;
	struct rfuse_pages *rp = &ria->rp;
	struct fuse_write_in *in = (struct fuse_write_in *)&r_req->args;

	in->fh = ff->fh;
	in->offset = pos;
	in->size = count;
	
	r_req->in.opcode = FUSE_WRITE;
	r_req->in.nodeid = ff->nodeid;
	r_req->in.arglen[0] = count;

	/* Why save rp in r_req->rp? 
		rp is the data structure where the pages are saved.
		When the fuse daemon read from the r_req, it should need a way
		to access the pages to copy to the user space.
		Therefore we need a pointer to point to the rp structure.
		The original fuse could just use the "container_of" MACRO(or function)
		instead of keeping a pointer. However, this was capable because the 
		rp, request was allocated statically. We(RFUSE) can't use this
	*/
	ria->write.in.size = count;
	ria->write.in.offset = pos;
	r_req->rp = rp;
}

static ssize_t rfuse_send_write_pages(struct rfuse_io_args *ria,
				     struct kiocb *iocb, struct inode *inode,
				     loff_t pos, size_t count)
{
	struct rfuse_pages *rp = &ria->rp;
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct fuse_mount *fm = ff->fm;
	
	struct fuse_write_in *in;
	struct fuse_write_out *out;
	unsigned int offset, i;
	bool short_write;
	int err;

	ria->r_req->in_pages = true;

	for (i = 0; i < rp->num_pages; i++)
		rfuse_wait_on_page_writeback(inode, rp->pages[i]->index);

	rfuse_write_args_fill(ria, ff, pos, count);

	in = (struct fuse_write_in *)&ria->r_req->args;
	in->flags = rfuse_write_flags(iocb);
	if (fm->fc->handle_killpriv_v2 && !capable(CAP_FSETID))
		in->write_flags |= FUSE_WRITE_KILL_SUIDGID;

	err = rfuse_simple_request(ria->r_req);
	out = (struct fuse_write_out *)&ria->r_req->args;
	if (!err && out->size > count)
		err = -EIO;

	short_write = out->size < count;
	offset = rp->descs[0].offset;
	count = out->size;
	for (i = 0; i < rp->num_pages; i++) {
		struct page *page = rp->pages[i];

		if (err) {
			ClearPageUptodate(page);
		} else {
			if (count >= PAGE_SIZE - offset)
				count -= PAGE_SIZE - offset;
			else {
				if (short_write)
					ClearPageUptodate(page);
				count = 0;
			}
			offset = 0;
		}
		if (ria->write.page_locked && (i == rp->num_pages - 1))
			unlock_page(page);
		put_page(page);
	}

	return err;
}

ssize_t rfuse_perform_write(struct kiocb *iocb, struct address_space *mapping, struct iov_iter *ii, loff_t pos){
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	int err = 0;
	ssize_t res = 0;

	if (inode->i_size < pos + iov_iter_count(ii))
		set_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);

	do {
		ssize_t count;
		struct rfuse_io_args ria = {};
		struct rfuse_pages *rp = &ria.rp;
		struct rfuse_req *r_req;
		unsigned int nr_pages = rfuse_wr_pages(pos, iov_iter_count(ii), fc->max_pages);

		rp->pages = fuse_pages_alloc(nr_pages, GFP_KERNEL, &rp->descs);
		if (!rp->pages) {
			err = -ENOMEM;
			break;
		}

   		r_req = rfuse_get_req(fm, false, false); 
		ria.r_req = r_req;

		count = rfuse_fill_write_pages(&ria, mapping, ii, pos, nr_pages);
		if (count <= 0) {
			err = count;
		} else {
			err = rfuse_send_write_pages(&ria, iocb, inode, pos, count);
			if (!err) {
				struct fuse_write_out *out = (struct fuse_write_out *)&ria.r_req->args;
				size_t num_written = out->size;

				res += num_written;
				pos += num_written;

				/* break out of the loop on short write */
				if (num_written != count)
					err = -EIO;
			}
		}
		rfuse_put_request(r_req); 
		kfree(rp->pages);
	} while (!err && iov_iter_count(ii));

	if (res > 0)
		fuse_write_update_size(inode, pos);

	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	fuse_invalidate_attr(inode);

	return res > 0 ? res : err;
}

static ssize_t rfuse_send_write(struct rfuse_io_args *ria, loff_t pos, size_t count, fl_owner_t owner)
{
	struct kiocb *iocb = ria->io->iocb;
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct fuse_mount *fm = ff->fm;
	struct fuse_write_in *inarg;
	struct fuse_write_out *out;
	ssize_t outsize;
	ssize_t err;
	struct rfuse_req *r_req;

	/* Allocate rfuse request for write) */
	if (ria->io->async) {
		r_req = rfuse_get_req(fm, true, false);
	} else {
		r_req = rfuse_get_req(fm, false, false);
	}
	ria->r_req = r_req;
	ria->r_req->in_pages = true;

	/* Initialize write in header */
	inarg = (struct fuse_write_in *)&r_req->args;
	rfuse_write_args_fill(ria, ff, pos, count);
	inarg->flags = rfuse_write_flags(iocb);
	if (owner != NULL) {
		inarg->write_flags |= FUSE_WRITE_LOCKOWNER;
		inarg->lock_owner = fuse_lock_owner_id(fm->fc, owner);
	}
	if (!capable(CAP_FSETID))
		inarg->write_flags |= FUSE_WRITE_KILL_SUIDGID;

	/* Send request */
	if (ria->io->async)
		return rfuse_async_req_send(fm, ria, count);
	
	err = rfuse_simple_request(r_req);
	out = (struct fuse_write_out *)&ria->r_req->args;
	if (!err && out->size > count)
		err = -EIO;
	outsize = out->size;
	rfuse_put_request(r_req);

	return err ?: outsize;
}

/* Writeback of dirty page*/

static void rfuse_send_writepage(struct fuse_mount *fm, struct rfuse_writepage_args *r_wpa, loff_t size);

static struct rfuse_writepage_args *rfuse_insert_writeback(struct rb_root *root,
						struct rfuse_writepage_args *wpa)
{
	pgoff_t idx_from = wpa->ria.write.in.offset >> PAGE_SHIFT;
	pgoff_t idx_to = idx_from + wpa->ria.rp.num_pages - 1;
	struct rb_node **p = &root->rb_node;
	struct rb_node  *parent = NULL;

	WARN_ON(!wpa->ria.rp.num_pages);
	while (*p) {
		struct rfuse_writepage_args *curr;
		pgoff_t curr_index;

		parent = *p;
		curr = rb_entry(parent, struct rfuse_writepage_args,
				writepages_entry);
		WARN_ON(curr->inode != wpa->inode);
		curr_index = curr->ria.write.in.offset >> PAGE_SHIFT;

		if (idx_from >= curr_index + curr->ria.rp.num_pages)
			p = &(*p)->rb_right;
		else if (idx_to < curr_index)
			p = &(*p)->rb_left;
		else
			return curr;
	}

	rb_link_node(&wpa->writepages_entry, parent, p);
	rb_insert_color(&wpa->writepages_entry, root);
	return NULL;
}

static void tree_insert(struct rb_root *root, struct rfuse_writepage_args *r_wpa)
{
	WARN_ON(rfuse_insert_writeback(root, r_wpa));
}

static struct fuse_file *__rfuse_write_file_get(struct fuse_inode *fi)
{
	struct fuse_file *ff = NULL;

	spin_lock(&fi->lock);
	if (!list_empty(&fi->write_files)) {
		ff = list_entry(fi->write_files.next, struct fuse_file,
				write_entry);
		rfuse_file_get(ff);
	}
	spin_unlock(&fi->lock);

	return ff;
}

static struct fuse_file *rfuse_write_file_get(struct fuse_inode *fi)
{
	struct fuse_file *ff = __rfuse_write_file_get(fi);
	WARN_ON(!ff);
	return ff;
}

static void rfuse_writepage_add_to_bucket(struct fuse_conn *fc,
					 struct rfuse_writepage_args *wpa)
{
	if (!fc->sync_fs)
		return;

	rcu_read_lock();
	/* Prevent resurrection of dead bucket in unlikely race with syncfs */
	do {
		wpa->bucket = rcu_dereference(fc->curr_bucket);
	} while (unlikely(!atomic_inc_not_zero(&wpa->bucket->count)));
	rcu_read_unlock();
}

static inline void rfuse_sync_bucket_dec(struct fuse_sync_bucket *bucket)
{
	/* Need RCU protection to prevent use after free after the decrement */
	rcu_read_lock();
	if (atomic_dec_and_test(&bucket->count))
		wake_up(&bucket->waitq);
	rcu_read_unlock();
}

static struct rfuse_writepage_args *rfuse_writepage_args_alloc(void)
{
	struct rfuse_writepage_args *r_wpa;
	struct rfuse_pages *rp;

	r_wpa = kzalloc(sizeof(*r_wpa), GFP_NOFS);
	if (r_wpa) {
		rp = &r_wpa->ria.rp;
		rp->num_pages = 0;
		rp->pages = fuse_pages_alloc(1, GFP_NOFS, &rp->descs);
		if (!rp->pages) {
			kfree(r_wpa);
			r_wpa = NULL;
		}
	}
	return r_wpa;

}

static void rfuse_writepage_finish(struct fuse_mount *fm,
				  struct rfuse_writepage_args *r_wpa)
{
	struct rfuse_pages *rp = &r_wpa->ria.rp;
	struct inode *inode = r_wpa->inode;
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct backing_dev_info *bdi = inode_to_bdi(inode);
	int i;

	for (i = 0; i < rp->num_pages; i++) {
		dec_wb_stat(&bdi->wb, WB_WRITEBACK);
		dec_node_page_state(rp->pages[i], NR_WRITEBACK_TEMP);
		wb_writeout_inc(&bdi->wb);
	}
	wake_up(&fi->page_waitq);
}

static void rfuse_writepage_free(struct rfuse_writepage_args *r_wpa)
{
	struct rfuse_req *r_req = r_wpa->ria.r_req;
	struct rfuse_pages *rp = &r_wpa->ria.rp;
	int i;

	if (r_wpa->bucket)
		rfuse_sync_bucket_dec(r_wpa->bucket);

	for (i = 0; i < rp->num_pages; i++)
		__free_page(rp->pages[i]);

	if (r_wpa->ria.ff)
		rfuse_file_put(r_wpa->ria.ff, r_req, false, false);

	kfree(rp->pages);
	kfree(r_wpa);
}

static void rfuse_writepage_end(struct fuse_mount *fm, struct rfuse_req *r_req,
			       int error)
{
	struct rfuse_pages *rp = r_req->rp;
	struct rfuse_io_args *ria = container_of(rp, typeof(*ria), rp);
	struct rfuse_writepage_args *r_wpa =
		container_of(ria, typeof(*r_wpa), ria);

	struct inode *inode = r_wpa->inode;
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_conn *fc = get_fuse_conn(inode);

	mapping_set_error(inode->i_mapping, error);
	/*
	 * A writeback finished and this might have updated mtime/ctime on
	 * server making local mtime/ctime stale.  Hence invalidate attrs.
	 * Do this only if writeback_cache is not enabled.  If writeback_cache
	 * is enabled, we trust local ctime/mtime.
	 */
	if (!fc->writeback_cache)
		fuse_invalidate_attr(inode);
	spin_lock(&fi->lock);
	rb_erase(&r_wpa->writepages_entry, &fi->writepages);
	while (r_wpa->next) {
		struct fuse_mount *fm = get_fuse_mount(inode);
		struct fuse_write_in *inarg = (struct fuse_write_in *)&r_req->args;
		struct rfuse_writepage_args *next = r_wpa->next;

		r_wpa->next = next->next;
		next->next = NULL;
		next->ria.ff = rfuse_file_get(r_wpa->ria.ff);
		tree_insert(&fi->writepages, next);

		rfuse_send_writepage(fm, next, inarg->offset + inarg->size);
	}
	fi->writectr--;
	rfuse_writepage_finish(fm, r_wpa);
	spin_unlock(&fi->lock);
	rfuse_writepage_free(r_wpa);
}

/* Called under fi->lock, may release and reacquire it */
static void rfuse_send_writepage(struct fuse_mount *fm,
				struct rfuse_writepage_args *r_wpa, loff_t size)
__releases(fi->lock)
__acquires(fi->lock)
{
	struct rfuse_writepage_args *aux, *next;
	struct fuse_inode *fi = get_fuse_inode(r_wpa->inode);
	struct fuse_write_in *inarg;
	struct rfuse_req *r_req;
	struct rfuse_io_args *ria = &r_wpa->ria;
	__u64 data_size = r_wpa->ria.rp.num_pages * PAGE_SIZE;
	int err;

	r_req = try_rfuse_get_req(fm, true, true, &fi->lock);

	ria->r_req = r_req;
	r_req->in_pages = true;
	r_req->nocreds = true;

	rfuse_write_args_fill(&r_wpa->ria, r_wpa->ria.ff, r_wpa->pos, 0);
	inarg = (struct fuse_write_in *)&r_req->args;

	fi->writectr++;
	if (inarg->offset + data_size <= size) {
		inarg->size = data_size;
	} else if (inarg->offset < size) {
		inarg->size = size - inarg->offset;
	} else {
		/* Got truncated off completely */
		goto out_free;
	}

	r_req->in.arglen[0] = inarg->size;
	r_req->end = rfuse_writepage_end;

	err = rfuse_simple_background(fm, r_req);
	/* Fails on broken connection only */
	if (unlikely(err))
		goto out_free;

	return;

 out_free:
	fi->writectr--;
	rb_erase(&r_wpa->writepages_entry, &fi->writepages);
	rfuse_writepage_finish(fm, r_wpa);
	spin_unlock(&fi->lock);

	/* After rfuse_writepage_finish() aux request list is private */
	for (aux = r_wpa->next; aux; aux = next) {
		next = aux->next;
		aux->next = NULL;
		rfuse_writepage_free(aux);
	}

	rfuse_writepage_free(r_wpa);
	spin_lock(&fi->lock);
}

void rfuse_flush_writepages(struct inode *inode)
__releases(fi->lock)
__acquires(fi->lock)
{
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	loff_t crop = i_size_read(inode);
	struct rfuse_writepage_args *r_wpa;

	while (fi->writectr >= 0 && !list_empty(&fi->queued_writes)) {
		r_wpa = list_entry(fi->queued_writes.next,
				 struct rfuse_writepage_args, queue_entry);
		list_del_init(&r_wpa->queue_entry);
		rfuse_send_writepage(fm, r_wpa, crop);
	}
}

int rfuse_writepage_locked(struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct rfuse_writepage_args *r_wpa;
	struct rfuse_pages *rp;
	struct page *tmp_page;
	int error = -ENOMEM;

	set_page_writeback(page);

	r_wpa = rfuse_writepage_args_alloc();
	if (!r_wpa)
		goto err;
	rp = &r_wpa->ria.rp;

	tmp_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
	if (!tmp_page)
		goto err_free;

	error = -EIO;
	r_wpa->ria.ff = rfuse_write_file_get(fi);
	if (!r_wpa->ria.ff)
		goto err_nofile;

	rfuse_writepage_add_to_bucket(fc, r_wpa);
	r_wpa->pos = page_offset(page);

	copy_highpage(tmp_page, page);
	r_wpa->ria.write.in.write_flags |= FUSE_WRITE_CACHE;
	r_wpa->next = NULL;

	rp->num_pages = 1;
	rp->pages[0] = tmp_page;
	rp->descs[0].offset = 0;
	rp->descs[0].length = PAGE_SIZE;
	r_wpa->inode = inode;

	inc_wb_stat(&inode_to_bdi(inode)->wb, WB_WRITEBACK);
	inc_node_page_state(tmp_page, NR_WRITEBACK_TEMP);

	spin_lock(&fi->lock);
	tree_insert(&fi->writepages, r_wpa);
	list_add_tail(&r_wpa->queue_entry, &fi->queued_writes);
	rfuse_flush_writepages(inode);
	spin_unlock(&fi->lock);

	end_page_writeback(page);

	return 0;

err_nofile:
	__free_page(tmp_page);
err_free:
	kfree(r_wpa);
err:
	mapping_set_error(page->mapping, error);
	end_page_writeback(page);
	return error;
}

int rfuse_writepage(struct page *page, struct writeback_control *wbc)
{
	int err;

	if (rfuse_page_is_writeback(page->mapping->host, page->index)) {
		/*
		 * ->writepages() should be called for sync() and friends.  We
		 * should only get here on direct reclaim and then we are
		 * allowed to skip a page which is already in flight
		 */
		WARN_ON(wbc->sync_mode == WB_SYNC_ALL);

		redirty_page_for_writepage(wbc, page);
		unlock_page(page);

		return 0;
	}

	err = rfuse_writepage_locked(page);
	unlock_page(page);

	return err;
}

struct rfuse_fill_wb_data {
	struct rfuse_writepage_args *r_wpa;
	struct fuse_file *ff;
	struct inode *inode;
	struct page **orig_pages;
	unsigned int max_pages;
};

static bool rfuse_pages_realloc(struct rfuse_fill_wb_data *data)
{
	struct rfuse_pages *rp = &data->r_wpa->ria.rp;
	struct fuse_conn *fc = get_fuse_conn(data->inode);
	struct page **pages;
	struct fuse_page_desc *descs;
	unsigned int npages = min_t(unsigned int,
				    max_t(unsigned int, data->max_pages * 2,
					  FUSE_DEFAULT_MAX_PAGES_PER_REQ),
				    fc->max_pages);
	WARN_ON(npages <= data->max_pages);

	pages = fuse_pages_alloc(npages, GFP_NOFS, &descs);
	if (!pages)
		return false;

	memcpy(pages, rp->pages, sizeof(struct page *) * rp->num_pages);
	memcpy(descs, rp->descs, sizeof(struct fuse_page_desc) * rp->num_pages);
	kfree(rp->pages);
	rp->pages = pages;
	rp->descs = descs;
	data->max_pages = npages;

	return true;
}

static void rfuse_writepages_send(struct rfuse_fill_wb_data *data)
{
	struct rfuse_writepage_args *r_wpa = data->r_wpa;
	struct inode *inode = data->inode;
	struct fuse_inode *fi = get_fuse_inode(inode);
	int num_pages = r_wpa->ria.rp.num_pages;
	int i;

	r_wpa->ria.ff = rfuse_file_get(data->ff);
	spin_lock(&fi->lock);
	list_add_tail(&r_wpa->queue_entry, &fi->queued_writes);
	rfuse_flush_writepages(inode);
	spin_unlock(&fi->lock);

	for (i = 0; i < num_pages; i++)
		end_page_writeback(data->orig_pages[i]);
}

static bool rfuse_writepage_add(struct rfuse_writepage_args *new_r_wpa,
			       struct page *page)
{
	struct fuse_inode *fi = get_fuse_inode(new_r_wpa->inode);
	struct rfuse_writepage_args *tmp;
	struct rfuse_writepage_args *old_r_wpa;
	struct rfuse_pages *new_rp = &new_r_wpa->ria.rp;

	WARN_ON(new_rp->num_pages != 0);
	new_rp->num_pages = 1;

	spin_lock(&fi->lock);
	old_r_wpa = rfuse_insert_writeback(&fi->writepages, new_r_wpa);
	if (!old_r_wpa) {
		spin_unlock(&fi->lock);
		return true;
	}

	for (tmp = old_r_wpa->next; tmp; tmp = tmp->next) {
		pgoff_t curr_index;

		WARN_ON(tmp->inode != new_r_wpa->inode);
		curr_index = tmp->ria.write.in.offset >> PAGE_SHIFT;
		if (curr_index == page->index) {
			WARN_ON(tmp->ria.rp.num_pages != 1);
			swap(tmp->ria.rp.pages[0], new_rp->pages[0]);
			break;
		}
	}

	if (!tmp) {
		new_r_wpa->next = old_r_wpa->next;
		old_r_wpa->next = new_r_wpa;
	}

	spin_unlock(&fi->lock);

	if (tmp) {
		struct backing_dev_info *bdi = inode_to_bdi(new_r_wpa->inode);

		dec_wb_stat(&bdi->wb, WB_WRITEBACK);
		dec_node_page_state(new_rp->pages[0], NR_WRITEBACK_TEMP);
		wb_writeout_inc(&bdi->wb);
		rfuse_writepage_free(new_r_wpa);
	}

	return false;
}

static bool rfuse_writepage_need_send(struct fuse_conn *fc, struct page *page,
				     struct rfuse_pages *rp,
				     struct rfuse_fill_wb_data *data)
{
	WARN_ON(!rp->num_pages);

	/*
	 * Being under writeback is unlikely but possible.  For example direct
	 * read to an mmaped fuse file will set the page dirty twice; once when
	 * the pages are faulted with get_user_pages(), and then after the read
	 * completed.
	 */
	if (rfuse_page_is_writeback(data->inode, page->index))
		return true;

	/* Reached max pages */
	if (rp->num_pages == fc->max_pages)
		return true;

	/* Reached max write bytes */
	if ((rp->num_pages + 1) * PAGE_SIZE > fc->max_write)
		return true;

	/* Discontinuity */
	if (data->orig_pages[rp->num_pages - 1]->index + 1 != page->index)
		return true;

	/* Need to grow the pages array?  If so, did the expansion fail? */
	if (rp->num_pages == data->max_pages && !rfuse_pages_realloc(data))
		return true;

	return false;
}


static int rfuse_writepages_fill(struct page *page,
		struct writeback_control *wbc, void *_data)
{
	struct rfuse_fill_wb_data *data = _data;
	struct rfuse_writepage_args *r_wpa = data->r_wpa;
	struct rfuse_pages *rp = &r_wpa->ria.rp;
	struct inode *inode = data->inode;
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct page *tmp_page;
	int err;

	if (!data->ff) {
		err = -EIO;
		data->ff = rfuse_write_file_get(fi);
		if (!data->ff)
			goto out_unlock;
	}

	if (r_wpa && rfuse_writepage_need_send(fc, page, rp, data)) {
		rfuse_writepages_send(data);
		data->r_wpa = NULL;
	}

	err = -ENOMEM;
	tmp_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
	if (!tmp_page)
		goto out_unlock;

	if (data->r_wpa == NULL) {
		err = -ENOMEM;
		r_wpa = rfuse_writepage_args_alloc();
		if (!r_wpa) {
			__free_page(tmp_page);
			goto out_unlock;
		}
		rfuse_writepage_add_to_bucket(fc, r_wpa);

		data->max_pages = 1;

		rp = &r_wpa->ria.rp;
		r_wpa->pos = page_offset(page);
		r_wpa->ria.write.in.write_flags |= FUSE_WRITE_CACHE;
		r_wpa->next = NULL;
		rp->num_pages = 0;
		r_wpa->inode = inode;
	}
	set_page_writeback(page);

	copy_highpage(tmp_page, page);
	rp->pages[rp->num_pages] = tmp_page;
	rp->descs[rp->num_pages].offset = 0;
	rp->descs[rp->num_pages].length = PAGE_SIZE;
	data->orig_pages[rp->num_pages] = page;

	inc_wb_stat(&inode_to_bdi(inode)->wb, WB_WRITEBACK);
	inc_node_page_state(tmp_page, NR_WRITEBACK_TEMP);

	err = 0;
	if (data->r_wpa) {
		/*
		 * Protected by fi->lock against concurrent access by
		 * fuse_page_is_writeback().
		 */
		spin_lock(&fi->lock);
		rp->num_pages++;
		spin_unlock(&fi->lock);
	} else if (rfuse_writepage_add(r_wpa, page)) {
		data->r_wpa = r_wpa;
	} else {
		end_page_writeback(page);
	}
out_unlock:
	unlock_page(page);

	return err;
}

int rfuse_writepages(struct address_space *mapping,
			   struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct rfuse_fill_wb_data data;
	int err;

	err = -EIO;
	if (fuse_is_bad(inode))
		goto out;

	data.inode = inode;
	data.r_wpa = NULL;
	data.ff = NULL;

	err = -ENOMEM;
	data.orig_pages = kcalloc(fc->max_pages,
				  sizeof(struct page *),
				  GFP_NOFS);
	if (!data.orig_pages)
		goto out;

	err = write_cache_pages(mapping, wbc, rfuse_writepages_fill, &data);
	if (data.r_wpa) {
		WARN_ON(!data.r_wpa->ria.rp.num_pages);
		rfuse_writepages_send(&data);
	}

	if (data.ff)
		rfuse_file_put(data.ff, NULL, false, false);

	kfree(data.orig_pages);
out:

	return err;
}

int rfuse_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned flags,
		struct page **pagep, void **fsdata)
{
	pgoff_t index = pos >> PAGE_SHIFT;
	struct fuse_conn *fc = get_fuse_conn(file_inode(file));
	struct page *page;
	loff_t fsize;
	int err = -ENOMEM;
	
	WARN_ON(!fc->writeback_cache);

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		goto error;

	rfuse_wait_on_page_writeback(mapping->host, page->index);

	if (PageUptodate(page) || len == PAGE_SIZE)
		goto success;
	/*
	 * Check if the start this page comes after the end of file, in which
	 * case the readpage can be optimized away.
	 */
	fsize = i_size_read(mapping->host);
	if (fsize <= (pos & PAGE_MASK)) {
		size_t off = pos & ~PAGE_MASK;
		if (off)
			zero_user_segment(page, 0, off);
		goto success;
	}
	err = rfuse_do_readpage(file, page);
	if (err)
		goto cleanup;
success:
	*pagep = page;
	return 0;

cleanup:
	unlock_page(page);
	put_page(page);
error:
	return err;
}

int rfuse_write_end(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned copied,
		struct page *page, void *fsdata)
{
	struct inode *inode = page->mapping->host;

	/* Haven't copied anything?  Skip zeroing, size extending, dirtying. */
	if (!copied)
		goto unlock;

	if (!PageUptodate(page)) {
		/* Zero any unwritten bytes at the end of the page */
		size_t endoff = (pos + copied) & ~PAGE_MASK;
		if (endoff)
			zero_user_segment(page, endoff, PAGE_SIZE);
		SetPageUptodate(page);
	}

	fuse_write_update_size(inode, pos + copied);
	set_page_dirty(page);

unlock:
	unlock_page(page);
	put_page(page);
	return copied;
}

int rfuse_launder_page(struct page *page)
{
	int err = 0;
	if (clear_page_dirty_for_io(page)) {
		struct inode *inode = page->mapping->host;

		/* Serialize with pending writeback for the same page */
		rfuse_wait_on_page_writeback(inode, page->index);
		err = rfuse_writepage_locked(page);
		if (!err)
			rfuse_wait_on_page_writeback(inode, page->index);
	}
	return err;
}

/************ 5. READ ************/


static void rfuse_short_read(struct inode *inode, u64 attr_ver, size_t num_read,
			    struct rfuse_pages *rp){
	struct fuse_conn *fc = get_fuse_conn(inode);

	/*
	 * If writeback_cache is enabled, a short read means there's a hole in
	 * the file.  Some data after the hole is in page cache, but has not
	 * reached the client fs yet.  So the hole is not present there.
	 */
	if (!fc->writeback_cache) {
		loff_t pos = page_offset(rp->pages[0]) + num_read;
		rfuse_read_update_size(inode, pos, attr_ver);
	}
}

/**
 * 
 * Before calling "rfuse_read_args_fill" you should
 * - Allocate a new rfuse_req
 * - save the allocated rfuse_req's pointer inside rfuse_io_args
 */

void rfuse_read_args_fill(struct rfuse_io_args *ria, struct file *file, loff_t pos,
			 size_t count, int opcode){

	struct fuse_file *ff = file->private_data;
	struct rfuse_req *r_req = ria->r_req;
	struct rfuse_pages *rp = &ria->rp;
	struct fuse_read_in *in = (struct fuse_read_in*)&r_req->args;
	// struct fuse_args *args = &ia->ap.args;

	in->fh = ff->fh;
	in->offset = pos;
	in->size = count;
	in->flags = file->f_flags;

	r_req->in.opcode = opcode;
	r_req->in.nodeid = ff->nodeid;
	r_req->out_argvar = true;

	r_req->out.arglen = count;
	r_req->rp = rp;
}

/**
 * rfuse_do_readpage 
 * - called during "fuse_readpage" & "fuse_write_begin"
 * - "fuse_readpage" is called through the address_space_operation ".readpage"
 * - "fuse_write_begin" is called before writing to a page, reads a page
 * 		before writing to it
 * 
 **/

int rfuse_do_readpage(struct file *file, struct page *page){
	struct inode *inode = page->mapping->host;
	struct fuse_mount *fm = get_fuse_mount(inode);
	loff_t pos = page_offset(page);
	struct fuse_page_desc desc = { .length = PAGE_SIZE };
	struct rfuse_io_args ria;
	struct rfuse_req *r_req;
	ssize_t res;
	u64 attr_ver;

	r_req = rfuse_get_req(fm, false, false);
	ria.r_req = r_req;

	ria.r_req->page_zeroing = true;
	ria.r_req->out_pages = true;
	ria.rp.num_pages = 1;
	ria.rp.pages = &page;
	ria.rp.descs = &desc;

	/*
	 * Page writeback can extend beyond the lifetime of the
	 * page-cache page, so make sure we read a properly synced
	 * page.
	 */
	rfuse_wait_on_page_writeback(inode, page->index);

	attr_ver = fuse_get_attr_version(fm->fc);

	/* Don't overflow end offset */
	if (pos + (desc.length - 1) == LLONG_MAX)
		desc.length--;

	rfuse_read_args_fill(&ria, file, pos, desc.length, FUSE_READ);
	res = rfuse_simple_request(r_req);
	rfuse_put_request(r_req);
	if (res < 0)
		return res;
	/*
	 * Short read means EOF.  If file size is larger, truncate it
	 */
	if (res < desc.length)
		rfuse_short_read(inode, attr_ver, res, &ria.rp);

	SetPageUptodate(page);

	return 0;
}

static struct rfuse_io_args *rfuse_io_alloc(struct fuse_io_priv *io, unsigned int npages)
{
	struct rfuse_io_args *ria;

	ria = kzalloc(sizeof(*ria), GFP_KERNEL);
	if (ria) {
		ria->io = io;
		ria->rp.pages = fuse_pages_alloc(npages, GFP_KERNEL,
						&ria->rp.descs);
		if (!ria->rp.pages) {
			printk("no rp.pages\n");
			kfree(ria);
			ria = NULL;
		}
	}
	return ria;
}

static void rfuse_io_free(struct rfuse_io_args *ria)
{
	kfree(ria->rp.pages);
	kfree(ria);
}

static void rfuse_readpages_end(struct fuse_mount *fm, struct rfuse_req *r_req, int err){
	int i;
	struct rfuse_pages *rp = r_req->rp;
	struct rfuse_io_args *ria = container_of(rp, typeof(*ria), rp);
	struct fuse_read_in *in = (struct fuse_read_in*)&r_req->args;
	size_t count = in->size;
	size_t num_read = r_req->out.arglen;
	struct address_space *mapping = NULL;

	for (i = 0; mapping == NULL && i < rp->num_pages; i++)
		mapping = rp->pages[i]->mapping;

	if (mapping) {
		struct inode *inode = mapping->host;

		/*
		 * Short read means EOF. If file size is larger, truncate it
		 */
		if (!err && num_read < count)
			rfuse_short_read(inode, ria->read.attr_ver, num_read, rp);

		fuse_invalidate_atime(inode);
	}

	for (i = 0; i < rp->num_pages; i++) {
		struct page *page = rp->pages[i];

		if (!err)
			SetPageUptodate(page);
		else
			SetPageError(page);
		unlock_page(page);
		put_page(page);
	}
	if (ria->ff)
		rfuse_file_put(ria->ff, r_req, false, false);

	rfuse_io_free(ria);
}

/**
 * rfuse_send_readpages 
 * - called during "fuse_readahead"
 * - "fuse_readahead" is called through the address_space_operation ".readahead"
 * - This is used in the generic_file_read_iter
 **/

static void rfuse_send_readpages(struct rfuse_io_args *ria, struct file *file){
	struct fuse_file *ff = file->private_data;
	struct fuse_mount *fm = ff->fm;
	struct rfuse_pages *rp = &ria->rp;
	loff_t pos = page_offset(rp->pages[0]);
	size_t count = rp->num_pages << PAGE_SHIFT;
	struct rfuse_req *r_req;

	ssize_t res;
	int err;

	if(fm->fc->async_read)
		r_req = try_rfuse_get_req(fm, true, false, NULL);
	else 
		r_req = rfuse_get_req(fm, false, false);
		
	ria->r_req = r_req;

	r_req->out_pages = true;
	r_req->page_zeroing = true;
	r_req->page_replace = true;

	/* Don't overflow end offset */
	if (pos + (count - 1) == LLONG_MAX) {
		count--;
		rp->descs[rp->num_pages - 1].length--;
	}
	WARN_ON((loff_t) (pos + count) < 0);

	rfuse_read_args_fill(ria, file, pos, count, FUSE_READ);
	ria->read.attr_ver = fuse_get_attr_version(fm->fc);
	if (fm->fc->async_read) {
		ria->ff = rfuse_file_get(ff);
		r_req->end = rfuse_readpages_end;
		err = rfuse_simple_background(fm, r_req);
		if (!err)
			return;
	} else {
		res = rfuse_simple_request(r_req);
		err = res < 0 ? res : 0;
		rfuse_readpages_end(fm, r_req, err);
		rfuse_put_request(r_req);
		return;
	}
	rfuse_readpages_end(fm, r_req, err);
}

void rfuse_readahead(struct readahead_control *rac)
{
	struct inode *inode = rac->mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	unsigned int i, max_pages, nr_pages = 0;

	if (fuse_is_bad(inode))
		return;

	max_pages = min_t(unsigned int, fc->max_pages,
			fc->max_read / PAGE_SIZE);

	for (;;) {
		struct rfuse_io_args *ria;
		struct rfuse_pages *rp;

		nr_pages = readahead_count(rac) - nr_pages;
		if (nr_pages > max_pages)
			nr_pages = max_pages;
		if (nr_pages == 0)
			break;
		ria = rfuse_io_alloc(NULL, nr_pages);
		if (!ria)
			return;
		rp = &ria->rp;
		nr_pages = __readahead_batch(rac, rp->pages, nr_pages);
		for (i = 0; i < nr_pages; i++) {
			rfuse_wait_on_page_writeback(inode,
						    readahead_index(rac) + i);
			rp->descs[i].length = PAGE_SIZE;
		}
		rp->num_pages = nr_pages;
		rfuse_send_readpages(ria, rac->file);
	}
}


static ssize_t rfuse_send_read(struct rfuse_io_args *ria, loff_t pos, size_t count, fl_owner_t owner)
{
	struct file *file = ria->io->iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct fuse_mount *fm = ff->fm;
	struct fuse_read_in *inarg;
	struct rfuse_req *r_req;
	int res;

	/* Allocate rfuse request for write) */
	if (ria->io->async) {
		r_req = rfuse_get_req(fm, true, false);
	} else {
		r_req = rfuse_get_req(fm, false, false);
	}
	ria->r_req = r_req;
	ria->r_req->out_pages = true;

	inarg = (struct fuse_read_in *)&r_req->args;
	rfuse_read_args_fill(ria, file, pos, count, FUSE_READ);
	if (owner != NULL) {
		inarg->read_flags |= FUSE_READ_LOCKOWNER;
		inarg->lock_owner = fuse_lock_owner_id(fm->fc, owner);
	}

	if (ria->io->async)
		return rfuse_async_req_send(fm, ria, count);
	res = rfuse_simple_request(r_req);
	rfuse_put_request(r_req);

	return res;
}

/************ 6. FALLOCATE  ************/

static int rfuse_writeback_range(struct inode *inode, loff_t start, loff_t end)
{
	int err = filemap_write_and_wait_range(inode->i_mapping, start, -1);

	if (!err)
		rfuse_sync_writes(inode);

	return err;
}

long rfuse_file_fallocate(struct file *file, int mode, loff_t offset, loff_t length)
{
	struct fuse_file *ff = file->private_data;
	struct inode *inode = file_inode(file);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_mount *fm = ff->fm;
	struct fuse_fallocate_in *inarg;

	int err;
	bool lock_inode = !(mode & FALLOC_FL_KEEP_SIZE) ||
			   (mode & (FALLOC_FL_PUNCH_HOLE |
				    FALLOC_FL_ZERO_RANGE));

	bool block_faults = FUSE_IS_DAX(inode) && lock_inode;
	struct rfuse_req *r_req;

	r_req = rfuse_get_req(fm, false, false);
	inarg = (struct fuse_fallocate_in *)&r_req->args;

	inarg->fh = ff->fh;
	inarg->offset = offset,
	inarg->length = length,
	inarg->mode = mode;

	r_req->in.opcode = FUSE_FALLOCATE;
	r_req->in.nodeid = ff->nodeid;

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |
		     FALLOC_FL_ZERO_RANGE))
		return -EOPNOTSUPP;

	if (fm->fc->no_fallocate)
		return -EOPNOTSUPP;

	if (lock_inode) {
		inode_lock(inode);
		if (block_faults) {
			filemap_invalidate_lock(inode->i_mapping);
			err = fuse_dax_break_layouts(inode, 0, 0);
			if (err)
				goto out;
		}

		if (mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE)) {
			loff_t endbyte = offset + length - 1;

			err = rfuse_writeback_range(inode, offset, endbyte);
			if (err)
				goto out;
		}
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    offset + length > i_size_read(inode)) {
		err = inode_newsize_ok(inode, offset + length);
		if (err)
			goto out;
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE))
		set_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);

	err = rfuse_simple_request(r_req);
	if (err == -ENOSYS) {
		fm->fc->no_fallocate = 1;
		err = -EOPNOTSUPP;
	}
	if (err)
		goto out;

	/* we could have extended the file */
	if (!(mode & FALLOC_FL_KEEP_SIZE)) {
		bool changed = fuse_write_update_size(inode, offset + length);

		if (changed && fm->fc->writeback_cache)
			file_update_time(file);
	}

	if (mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_ZERO_RANGE))
		truncate_pagecache_range(inode, offset, offset + length - 1);

	fuse_invalidate_attr(inode);

out:
	if (!(mode & FALLOC_FL_KEEP_SIZE))
		clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);

	if (block_faults)
		filemap_invalidate_unlock(inode->i_mapping);

	if (lock_inode)
		inode_unlock(inode);

	rfuse_put_request(r_req);
	return err;
}

int rfuse_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_file *ff;
	int err;

	ff = __rfuse_write_file_get(fi);
	err = rfuse_flush_times(inode, ff);
	if (ff)
		rfuse_file_put(ff, NULL, false, false);

	return err;
}
