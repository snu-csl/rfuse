#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/fs_context.h>
#include <linux/sched.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/iversion.h>
#include <linux/posix_acl.h>

/************ 0. Copy of original fuse functions ************/

/*
 * Allow writepages on inode
 *
 * Remove the bias from the writecounter and send any queued
 * writepages.
 */
static void __rfuse_release_nowrite(struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	BUG_ON(fi->writectr != FUSE_NOWRITE);
	fi->writectr = 0;
	fuse_flush_writepages(inode);
}

#if BITS_PER_LONG >= 64
static inline void __rfuse_dentry_settime(struct dentry *entry, u64 time)
{
	entry->d_fsdata = (void *) time;
}

static inline u64 rfuse_dentry_time(const struct dentry *entry)
{
	return (u64)entry->d_fsdata;
}

#else
union rfuse_dentry {
	u64 time;
	struct rcu_head rcu;
};

static inline void __rfuse_dentry_settime(struct dentry *dentry, u64 time)
{
	((union rfuse_dentry *) dentry->d_fsdata)->time = time;
}

static inline u64 rfuse_dentry_time(const struct dentry *entry)
{
	return ((union rfuse_dentry *) entry->d_fsdata)->time;
}
#endif

static bool rfuse_update_mtime(unsigned ivalid, bool trust_local_mtime)
{
	/* Always update if mtime is explicitly set  */
	if (ivalid & ATTR_MTIME_SET)
		return true;

	/* Or if kernel i_mtime is the official one */
	if (trust_local_mtime)
		return true;

	/* If it's an open(O_TRUNC) or an ftruncate(), don't update */
	if ((ivalid & ATTR_SIZE) && (ivalid & (ATTR_OPEN | ATTR_FILE)))
		return false;

	/* In all other cases update */
	return true;
}

/*
 * Calculate the time in jiffies until a dentry/attributes are valid
 */
static u64 rfuse_time_to_jiffies(u64 sec, u32 nsec)
{
	if (sec || nsec) {
		struct timespec64 ts = {
			sec,
			min_t(u32, nsec, NSEC_PER_SEC - 1)
		};

		return get_jiffies_64() + timespec64_to_jiffies(&ts);
	} else
		return 0;
}

static void rfuse_iattr_to_fattr(struct fuse_conn *fc, struct iattr *iattr,
			   struct fuse_setattr_in *arg, bool trust_local_cmtime)
{
	unsigned ivalid = iattr->ia_valid;

	if (ivalid & ATTR_MODE)
		arg->valid |= FATTR_MODE,   arg->mode = iattr->ia_mode;
	if (ivalid & ATTR_UID)
		arg->valid |= FATTR_UID,    arg->uid = from_kuid(fc->user_ns, iattr->ia_uid);
	if (ivalid & ATTR_GID)
		arg->valid |= FATTR_GID,    arg->gid = from_kgid(fc->user_ns, iattr->ia_gid);
	if (ivalid & ATTR_SIZE)
		arg->valid |= FATTR_SIZE,   arg->size = iattr->ia_size;
	if (ivalid & ATTR_ATIME) {
		arg->valid |= FATTR_ATIME;
		arg->atime = iattr->ia_atime.tv_sec;
		arg->atimensec = iattr->ia_atime.tv_nsec;
		if (!(ivalid & ATTR_ATIME_SET))
			arg->valid |= FATTR_ATIME_NOW;
	}
	if ((ivalid & ATTR_MTIME) && rfuse_update_mtime(ivalid, trust_local_cmtime)) {
		arg->valid |= FATTR_MTIME;
		arg->mtime = iattr->ia_mtime.tv_sec;
		arg->mtimensec = iattr->ia_mtime.tv_nsec;
		if (!(ivalid & ATTR_MTIME_SET) && !trust_local_cmtime)
			arg->valid |= FATTR_MTIME_NOW;
	}
	if ((ivalid & ATTR_CTIME) && trust_local_cmtime) {
		arg->valid |= FATTR_CTIME;
		arg->ctime = iattr->ia_ctime.tv_sec;
		arg->ctimensec = iattr->ia_ctime.tv_nsec;
	}
}

static void rfuse_advise_use_readdirplus(struct inode *dir)
{
	struct fuse_inode *fi = get_fuse_inode(dir);

	set_bit(FUSE_I_ADVISE_RDPLUS, &fi->state);
}

static u64 rfuse_attr_timeout(struct fuse_attr_out *o)
{
	return rfuse_time_to_jiffies(o->attr_valid, o->attr_valid_nsec);
}

static void rfuse_fillattr(struct inode *inode, struct fuse_attr *attr, struct kstat *stat)
{
	unsigned int blkbits;
	struct fuse_conn *fc = get_fuse_conn(inode);

	/* see the comment in fuse_change_attributes() */
	if (fc->writeback_cache && S_ISREG(inode->i_mode)) {
		attr->size = i_size_read(inode);
		attr->mtime = inode->i_mtime.tv_sec;
		attr->mtimensec = inode->i_mtime.tv_nsec;
		attr->ctime = inode->i_ctime.tv_sec;
		attr->ctimensec = inode->i_ctime.tv_nsec;
	}

	stat->dev = inode->i_sb->s_dev;
	stat->ino = attr->ino;
	stat->mode = (inode->i_mode & S_IFMT) | (attr->mode & 07777);
	stat->nlink = attr->nlink;
	stat->uid = make_kuid(fc->user_ns, attr->uid);
	stat->gid = make_kgid(fc->user_ns, attr->gid);
	stat->rdev = inode->i_rdev;
	stat->atime.tv_sec = attr->atime;
	stat->atime.tv_nsec = attr->atimensec;
	stat->mtime.tv_sec = attr->mtime;
	stat->mtime.tv_nsec = attr->mtimensec;
	stat->ctime.tv_sec = attr->ctime;
	stat->ctime.tv_nsec = attr->ctimensec;
	stat->size = attr->size;
	stat->blocks = attr->blocks;

	if (attr->blksize != 0)
		blkbits = ilog2(attr->blksize);
	else
		blkbits = inode->i_sb->s_blocksize_bits;

	stat->blksize = 1 << blkbits;
}

static void rfuse_dir_changed(struct inode *dir)
{
	fuse_invalidate_attr(dir);
	inode_maybe_inc_iversion(dir, false);
}


/*
 * Same as fuse_invalidate_entry_cache(), but also try to remove the
 * dentry from the hash
 */
static void rfuse_invalidate_entry(struct dentry *entry)
{
	d_invalidate(entry);
	fuse_invalidate_entry_cache(entry);
}


/************ 1. GETATTR ************/

int rfuse_do_getattr(struct inode *inode, struct kstat *stat, struct file *file){
	int err;
	struct fuse_getattr_in *inarg;
	struct fuse_attr_out *outarg;
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct rfuse_req *r_req;
	u64 attr_version;

	r_req = rfuse_get_req(fm, false, false);
	if(IS_ERR(r_req))
		return PTR_ERR(r_req);
		
	inarg = (struct fuse_getattr_in*)(&r_req->args);
	attr_version = fuse_get_attr_version(fm->fc);

	// 1. Fill inside the operation specific header
	if(file && S_ISREG(inode->i_mode)){
		struct fuse_file *ff = file->private_data;
		inarg->getattr_flags |= FUSE_GETATTR_FH;
		inarg->fh = ff->fh;
	}

	// 2. Fill inside the common header
	r_req->in.opcode = FUSE_GETATTR;
	r_req->in.nodeid = get_node_id(inode);
	// NO ARGUMENT

	err = rfuse_simple_request(r_req);
	
	outarg = (struct fuse_attr_out*)(&r_req->args);
	if(!err){
		if(fuse_invalid_attr(&outarg->attr) ||
		inode_wrong_type(inode, outarg->attr.mode)){
			fuse_make_bad(inode);
			err = -EIO;
		}
		else{
			fuse_change_attributes(inode, &outarg->attr,rfuse_attr_timeout(outarg),attr_version);
			if(stat)
				rfuse_fillattr(inode, &outarg->attr,stat);
		}
	}
	rfuse_put_request(r_req);
	
	return err;
}

/************ 2. LOOKUP ************/

static void rfuse_lookup_init(struct fuse_mount *fm, struct rfuse_req *r_req, u64 nodeid, const struct qstr *name){
	struct rfuse_arg* arg;
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(fm->fc, r_req->riq_id);
	unsigned int in_arg = rfuse_get_argument_buffer(fm, r_req->riq_id);
	unsigned int out_arg = rfuse_get_argument_buffer(fm, r_req->riq_id);

	arg = (struct rfuse_arg*)&riq->karg[in_arg];
	memset(arg,0,sizeof(struct rfuse_arg));

	// Copy the name into argument space
	memcpy(arg, (char*)name->name, name->len+1);

	r_req->in.opcode = FUSE_LOOKUP;
	r_req->in.nodeid = nodeid;
	r_req->in.arglen[0] = name->len+1;
	r_req->in.arg[0] = in_arg;
	r_req->out.arg = out_arg;
	r_req->out.arglen = sizeof(struct fuse_entry_out);
}

int rfuse_lookup_name(struct super_block *sb, u64 nodeid, const struct qstr *name, struct rfuse_req *r_req, struct inode **inode){
	struct fuse_mount *fm = get_fuse_mount_super(sb);
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(fm->fc, r_req->riq_id);
	u64 attr_version;
	int err;
	struct fuse_entry_out *outarg;

	*inode = NULL;
	err = -ENAMETOOLONG;
	if (name->len > FUSE_NAME_MAX) 
		goto out;

	attr_version = fuse_get_attr_version(fm->fc);

	rfuse_lookup_init(fm,r_req,nodeid,name); // Rfuse test
	err = rfuse_simple_request(r_req); // Rfuse test

	outarg = (struct fuse_entry_out*)&riq->karg[r_req->out.arg];
	/* Zero nodeid is same as -ENOENT, but with valid timeout */
	if(err || !outarg->nodeid)	
		goto out;

	err = -EIO;
	if (!outarg->nodeid)
		goto out;	
	if (fuse_invalid_attr(&outarg->attr))
		goto out;	
	*inode = fuse_iget(sb, outarg->nodeid, outarg->generation,
			   &outarg->attr, entry_attr_timeout(outarg),
			   attr_version);
	err = -ENOMEM;
	if (!*inode) { // queue the forget to the forget queue
		rfuse_queue_forget(fm->fc, outarg->nodeid, 1);
		goto out;	
	}
	err = 0;
out:
	return err;
}

struct dentry *rfuse_lookup(struct inode *dir, struct dentry *entry, unsigned int flags){
	int err;
	struct inode *inode;
	struct rfuse_req *r_req;
	struct fuse_entry_out *outarg;
	struct dentry *newent;
	struct fuse_mount *fm = get_fuse_mount(dir);
	struct rfuse_iqueue *riq;
	bool outarg_valid = true;
	bool locked;

	if (fuse_is_bad(dir))
		return ERR_PTR(-EIO);

	r_req = rfuse_get_req(fm, false, false); // Rfuse test
	locked = fuse_lock_inode(dir);
	err = rfuse_lookup_name(dir->i_sb, get_node_id(dir), &entry->d_name, r_req, &inode);
	fuse_unlock_inode(dir, locked);
	
	riq = rfuse_get_specific_iqueue(fm->fc, r_req->riq_id);
	outarg = (struct fuse_entry_out*)&riq->karg[r_req->out.arg];

	if (err == -ENOENT) {
		outarg_valid = false;
		err = 0;
	}
	if (err)
		goto out_err;

	err = -EIO;
	if (inode && get_node_id(inode) == FUSE_ROOT_ID)
		goto out_iput;

	newent = d_splice_alias(inode, entry);
	err = PTR_ERR(newent);
	if (IS_ERR(newent))
		goto out_err;

	entry = newent ? newent : entry;
	if (outarg_valid)
		fuse_change_entry_timeout(entry, outarg);
	else
		fuse_invalidate_entry_cache(entry);

	if (inode)
		rfuse_advise_use_readdirplus(dir);

	rfuse_put_request(r_req); 
	return newent;

 out_iput:
	iput(inode);

 out_err:
 	rfuse_put_request(r_req); 
	return ERR_PTR(err);
}


/*
 * Check whether the dentry is still valid
 *
 * If the entry validity timeout has expired and the dentry is
 * positive, try to redo the lookup.  If the lookup results in a
 * different inode, then let the VFS invalidate the dentry and redo
 * the lookup once more.  If the lookup results in the same inode,
 * then refresh the attributes, timeouts and mark the dentry valid.
 */
int rfuse_dentry_revalidate(struct dentry *entry, unsigned int flags){
	struct inode *inode;
	struct dentry *parent;
	struct fuse_mount *fm;
	struct fuse_inode *fi;
	struct rfuse_req *r_req;
	bool rfuse_req_allocated = false;
	int ret;

	inode = d_inode_rcu(entry);
	if (inode && fuse_is_bad(inode))
		goto invalid;
	else if (time_before64(rfuse_dentry_time(entry), get_jiffies_64()) ||
		 (flags & (LOOKUP_EXCL | LOOKUP_REVAL))) {
		struct fuse_entry_out *outarg;
		struct rfuse_iqueue *riq; 
		u64 attr_version;

		/* For negative dentries, always do a fresh lookup */
		if (!inode)
			goto invalid;

		ret = -ECHILD;
		if (flags & LOOKUP_RCU)
			goto out;

		fm = get_fuse_mount(inode);
		
		attr_version = fuse_get_attr_version(fm->fc);
		parent = dget_parent(entry);

		r_req = rfuse_get_req(fm, false, false); // Rfuse test
		riq = rfuse_get_specific_iqueue(fm->fc, r_req->riq_id);
		rfuse_lookup_init(fm,r_req,get_node_id(d_inode(parent)),&entry->d_name);
		ret = rfuse_simple_request(r_req);
		rfuse_req_allocated = true;

		outarg = (struct fuse_entry_out*)&riq->karg[r_req->out.arg];
		dput(parent);
		/* Zero nodeid is same as -ENOENT */
		if (!ret && !outarg->nodeid)
			ret = -ENOENT;
		if (!ret) {
			fi = get_fuse_inode(inode);
			if (outarg->nodeid != get_node_id(inode) ||
			    (bool) IS_AUTOMOUNT(inode) != (bool) (outarg->attr.flags & FUSE_ATTR_SUBMOUNT)) {
				rfuse_queue_forget(fm->fc,outarg->nodeid, 1);
				goto invalid;
			}
			spin_lock(&fi->lock);
			fi->nlookup++;
			spin_unlock(&fi->lock);
		}

		if (ret == -ENOMEM)
			goto out;
		if (ret || fuse_invalid_attr(&outarg->attr) ||
		    fuse_stale_inode(inode, outarg->generation, &outarg->attr))
			goto invalid;


		forget_all_cached_acls(inode);
		fuse_change_attributes(inode, &outarg->attr,
				       entry_attr_timeout(outarg),
				       attr_version);
		fuse_change_entry_timeout(entry, outarg);
	} else if (inode) {
		fi = get_fuse_inode(inode);
		if (flags & LOOKUP_RCU) {
			if (test_bit(FUSE_I_INIT_RDPLUS, &fi->state)){
				return -ECHILD;
			}
		} else if (test_and_clear_bit(FUSE_I_INIT_RDPLUS, &fi->state)) {
			parent = dget_parent(entry);
			rfuse_advise_use_readdirplus(d_inode(parent));
			dput(parent);
		}
	}
	ret = 1;
out:
	if(rfuse_req_allocated)
		rfuse_put_request(r_req);
	return ret;

invalid:
	ret = 0;
	goto out;


}


/************ 3. SETATTR ************/

int rfuse_do_setattr(struct dentry *dentry, struct iattr *attr, struct file *file){
	struct inode *inode = d_inode(dentry);
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct rfuse_req *r_req;
	struct fuse_conn *fc = fm->fc;
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct address_space *mapping = inode->i_mapping;
	struct fuse_setattr_in *inarg;
	struct fuse_attr_out *outarg;
	bool is_truncate = false;
	bool is_wb = fc->writeback_cache;
	loff_t oldsize;
	int err;
	bool trust_local_cmtime = is_wb && S_ISREG(inode->i_mode);
	bool fault_blocked = false;

	if (!fc->default_permissions)
		attr->ia_valid |= ATTR_FORCE;

	err = setattr_prepare(&init_user_ns, dentry, attr);
	if (err)
		return err;

	if (attr->ia_valid & ATTR_SIZE) {
		if (WARN_ON(!S_ISREG(inode->i_mode)))
			return -EIO;
		is_truncate = true;
	}

	if (FUSE_IS_DAX(inode) && is_truncate) {
		filemap_invalidate_lock(mapping);
		fault_blocked = true;
		err = fuse_dax_break_layouts(inode, 0, 0);
		if (err) {
			filemap_invalidate_unlock(mapping);
			return err;
		}
	}

	if (attr->ia_valid & ATTR_OPEN) {
		/* This is coming from open(..., ... | O_TRUNC); */
		WARN_ON(!(attr->ia_valid & ATTR_SIZE));
		WARN_ON(attr->ia_size != 0);
		if (fc->atomic_o_trunc) {
			/*
			 * No need to send request to userspace, since actual
			 * truncation has already been done by OPEN.  But still
			 * need to truncate page cache.
			 */
			i_size_write(inode, 0);
			truncate_pagecache(inode, 0);
			goto out;
		}
		file = NULL;
	}

	/* Flush dirty data/metadata before non-truncate SETATTR */
	if (is_wb && S_ISREG(inode->i_mode) &&
	    attr->ia_valid &
			(ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_MTIME_SET |
			 ATTR_TIMES_SET)) {
		err = write_inode_now(inode, true);
		if (err)
			return err;

		fuse_set_nowrite(inode);
		fuse_release_nowrite(inode);
	}

	if (is_truncate) {
		fuse_set_nowrite(inode);
		set_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
		if (trust_local_cmtime && attr->ia_size != inode->i_size)
			attr->ia_valid |= ATTR_MTIME | ATTR_CTIME;
	}


	r_req = rfuse_get_req(fm, false, false);
	inarg = (struct fuse_setattr_in*)(&r_req->args);

	rfuse_iattr_to_fattr(fc, attr, inarg, trust_local_cmtime);

	if (file) {
		struct fuse_file *ff = file->private_data;
		inarg->valid |= FATTR_FH;
		inarg->fh = ff->fh;
	}

	/* Kill suid/sgid for non-directory chown unconditionally */
	if (fc->handle_killpriv_v2 && !S_ISDIR(inode->i_mode) &&
	    attr->ia_valid & (ATTR_UID | ATTR_GID))
		inarg->valid |= FATTR_KILL_SUIDGID;

	if (attr->ia_valid & ATTR_SIZE) {
		/* For mandatory locking in truncate */
		inarg->valid |= FATTR_LOCKOWNER;
		inarg->lock_owner = fuse_lock_owner_id(fc, current->files);

		/* Kill suid/sgid for truncate only if no CAP_FSETID */
		if (fc->handle_killpriv_v2 && !capable(CAP_FSETID))
			inarg->valid |= FATTR_KILL_SUIDGID;
	}

	r_req->in.opcode = FUSE_SETATTR;
	r_req->in.nodeid = get_node_id(inode);
	// NO ARGUMENT
	err = rfuse_simple_request(r_req); // Sends this request to the pending queue and go to sleep
	
	outarg = (struct fuse_attr_out*)(&r_req->args);
	if (err) {
		if (err == -EINTR)
			fuse_invalidate_attr(inode);
		goto error;
	}

	if (fuse_invalid_attr(&outarg->attr) ||
	    inode_wrong_type(inode, outarg->attr.mode)) {
		fuse_make_bad(inode);
		err = -EIO;
		goto error;
	}

	spin_lock(&fi->lock);
	/* the kernel maintains i_mtime locally */
	if (trust_local_cmtime) {
		if (attr->ia_valid & ATTR_MTIME)
			inode->i_mtime = attr->ia_mtime;
		if (attr->ia_valid & ATTR_CTIME)
			inode->i_ctime = attr->ia_ctime;
		/* FIXME: clear I_DIRTY_SYNC? */
	}

	fuse_change_attributes_common(inode, &outarg->attr, rfuse_attr_timeout(outarg)); 
	oldsize = inode->i_size;
	/* see the comment in fuse_change_attributes() */
	if (!is_wb || is_truncate || !S_ISREG(inode->i_mode))
		i_size_write(inode, outarg->attr.size);

	if (is_truncate) {
		/* NOTE: this may release/reacquire fi->lock */
		__rfuse_release_nowrite(inode);
	}
	spin_unlock(&fi->lock);

	/*
	 * Only call invalidate_inode_pages2() after removing
	 * FUSE_NOWRITE, otherwise fuse_launder_page() would deadlock.
	 */
	if ((is_truncate || !is_wb) &&
	    S_ISREG(inode->i_mode) && oldsize != outarg->attr.size) {
		truncate_pagecache(inode, outarg->attr.size);
		invalidate_inode_pages2(mapping);
	}

	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	rfuse_put_request(r_req); 
out:
	if (fault_blocked)
		filemap_invalidate_unlock(mapping);
	return 0;

error:
	if (is_truncate)
		fuse_release_nowrite(inode);

	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	rfuse_put_request(r_req); 
	if (fault_blocked)
		filemap_invalidate_unlock(mapping);
	return err;
}


/************ 4. RMDIR ************/

int rfuse_rmdir(struct inode *dir, struct dentry *entry){
	int err;
	struct fuse_mount *fm = get_fuse_mount(dir);
	struct rfuse_req *r_req;
	struct rfuse_arg* arg;
	struct rfuse_iqueue *riq;
	unsigned int argument_index;

	if(fuse_is_bad(dir))
		return -EIO;
	
	r_req = rfuse_get_req(fm, false, false);
	riq = rfuse_get_specific_iqueue(fm->fc, r_req->riq_id);
	argument_index = rfuse_get_argument_buffer(fm, r_req->riq_id);
	arg = (struct rfuse_arg*)&riq->karg[argument_index];

	r_req->in.opcode = FUSE_RMDIR;
	r_req->in.nodeid = get_node_id(dir);
	r_req->in.arglen[0] = entry->d_name.len + 1;
	r_req->in.arg[0] = argument_index;

	memset(arg,0,sizeof(struct rfuse_arg));
	memcpy(arg, (char*)entry->d_name.name, entry->d_name.len + 1);

	err = rfuse_simple_request(r_req);
	rfuse_put_request(r_req); 

	if(!err){
		clear_nlink(d_inode(entry));
		rfuse_dir_changed(dir);
		fuse_invalidate_entry_cache(entry);
	}
	else if(err == -EINTR){
		rfuse_invalidate_entry(entry);
	}
	return err;
}

/************ 4. MKDIR  ************/

/*
	Code shared between mknod, mkdir, symlink and link
*/

static int rfuse_create_new_entry(struct fuse_mount *fm, struct rfuse_req *r_req,
			struct inode *dir, struct dentry *entry, umode_t mode){
	struct fuse_entry_out *outarg;
	unsigned int out_argument_index; // argument
	struct rfuse_arg* arg;
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(fm->fc, r_req->riq_id);
	struct inode *inode;
	struct dentry *d;
	int err;
	
	if (fuse_is_bad(dir))
		return -EIO;
	
	out_argument_index = rfuse_get_argument_buffer(fm, r_req->riq_id);
	arg = (struct rfuse_arg*)&riq->karg[out_argument_index]; // Argument
	memset(arg,0,sizeof(struct rfuse_arg));

	r_req->in.nodeid = get_node_id(dir);
	r_req->out.arg = out_argument_index;
	r_req->out.arglen = sizeof(struct fuse_entry_out);

	err = rfuse_simple_request(r_req);
	outarg = (struct fuse_entry_out*)&riq->karg[out_argument_index];
	if(err)
		goto out;
	
	err = -EIO;
	if (invalid_nodeid(outarg->nodeid) || fuse_invalid_attr(&outarg->attr))
		goto out;

	if ((outarg->attr.mode ^ mode) & S_IFMT)
		goto out;

	inode = fuse_iget(dir->i_sb, outarg->nodeid, outarg->generation,
			  &outarg->attr, entry_attr_timeout(outarg), 0);

	if (!inode) {
		rfuse_queue_forget(fm->fc,outarg->nodeid,1);
		return -ENOMEM;
	}

	d_drop(entry);
	d = d_splice_alias(inode, entry);
	if (IS_ERR(d))
		return PTR_ERR(d);

	if (d) {
		fuse_change_entry_timeout(d, outarg);
		dput(d);
	} else {
		fuse_change_entry_timeout(entry, outarg);
	}
	rfuse_dir_changed(dir);
	return 0;
out:
	return err;
}


int rfuse_mkdir(struct user_namespace *mnt_userns, struct inode *dir,
		      struct dentry *entry, umode_t mode)
{
	int err;
	struct fuse_mkdir_in *inarg; // operation specific header
	struct fuse_mount *fm = get_fuse_mount(dir);
	struct rfuse_req *r_req;
	struct rfuse_arg* arg;
	struct rfuse_iqueue *riq;
	unsigned int in_argument_index; // argument

	if (!fm->fc->dont_mask)
		mode &= ~current_umask();

	r_req = rfuse_get_req(fm, false, false);
	riq = rfuse_get_specific_iqueue(fm->fc, r_req->riq_id);
	in_argument_index = rfuse_get_argument_buffer(fm, r_req->riq_id);
	inarg = (struct fuse_mkdir_in*)(&r_req->args); // Specific header
	arg = (struct rfuse_arg*)&riq->karg[in_argument_index]; // Argument

	inarg->mode = mode;
	inarg->umask = current_umask();

	memcpy(arg, (char*)entry->d_name.name, entry->d_name.len + 1);

	r_req->in.opcode = FUSE_MKDIR;
	r_req->in.arg[0] = in_argument_index;
	r_req->in.arglen[0] = entry->d_name.len + 1;

	err = rfuse_create_new_entry(fm, r_req, dir, entry, S_IFDIR);
	rfuse_put_request(r_req);
	return err;
}


/************ 5. CREATE  ************/


int rfuse_create_open(struct inode *dir, struct dentry *entry,
			    struct file *file, unsigned int flags,
			    umode_t mode)
{
	int err;
	struct inode *inode;
	struct fuse_mount *fm = get_fuse_mount(dir);
	// struct fuse_forget_link *forget;
	struct rfuse_req *r_req;
	struct rfuse_arg *in_arg;
	struct rfuse_iqueue *riq;
	struct fuse_create_in *increate;
	struct fuse_open_out *outopen;
	unsigned int in_argument_index; // argument
	unsigned int out_argument_index; // argument
	struct fuse_entry_out *outentry;
	struct fuse_inode *fi;
	struct fuse_file *ff;

	/* Userspace expects S_IFREG in create mode */
	BUG_ON((mode & S_IFMT) != S_IFREG);

	// forget = fuse_alloc_forget();
	// err = -ENOMEM;
	// if (!forget)
	// 	goto out_err;

	err = -ENOMEM;
	ff = fuse_file_alloc(fm);
	if (!ff)
		goto out_put_forget_req;

	if (!fm->fc->dont_mask)
		mode &= ~current_umask();

	flags &= ~O_NOCTTY;

	r_req = rfuse_get_req(fm, false, false);
	riq = rfuse_get_specific_iqueue(fm->fc, r_req->riq_id);
	in_argument_index = rfuse_get_argument_buffer(fm, r_req->riq_id);
	increate = (struct fuse_create_in*)(&r_req->args); // Specific header
	in_arg = (struct rfuse_arg*)&riq->karg[in_argument_index]; // Argument

	increate->flags = flags;
	increate->mode = mode;
	increate->umask = current_umask();

	if (fm->fc->handle_killpriv_v2 && (flags & O_TRUNC) &&
	    !(flags & O_EXCL) && !capable(CAP_FSETID)) {
		increate->open_flags |= FUSE_OPEN_KILL_SUIDGID;
	}

	memset(in_arg, 0, sizeof(struct rfuse_arg));
	memcpy(in_arg, (char*)entry->d_name.name, entry->d_name.len + 1);
	
	r_req->in.opcode = FUSE_CREATE;
	r_req->in.nodeid = get_node_id(dir);
	r_req->in.arg[0] = in_argument_index;
	r_req->in.arglen[0] = entry->d_name.len + 1;

	out_argument_index = rfuse_get_argument_buffer(fm, r_req->riq_id);
	r_req->out.arg = out_argument_index;
	r_req->out.arglen = sizeof(struct fuse_entry_out);

	err = rfuse_simple_request(r_req);
	outentry = (struct fuse_entry_out*)&riq->karg[out_argument_index];
	outopen = (struct fuse_open_out*)&r_req->args;

	if (err)
		goto out_free_ff;

	err = -EIO;
	if (!S_ISREG(outentry->attr.mode) || invalid_nodeid(outentry->nodeid) ||
	    fuse_invalid_attr(&outentry->attr)) {
		goto out_free_ff;
	}

	ff->fh = outopen->fh;
	ff->nodeid = outentry->nodeid;
	ff->open_flags = outopen->open_flags;
	inode = fuse_iget(dir->i_sb, outentry->nodeid, outentry->generation,
			  &outentry->attr, entry_attr_timeout(outentry), 0);
	if (!inode) {
		flags &= ~(O_CREAT | O_EXCL | O_TRUNC);
		rfuse_sync_release(NULL, ff, flags);		
		rfuse_queue_forget(fm->fc, outentry->nodeid, 1);
		err = -ENOMEM;
		goto out_err;
	}
	d_instantiate(entry, inode);
	fuse_change_entry_timeout(entry, outentry);
	rfuse_dir_changed(dir);
	err = finish_open(file, entry, generic_file_open);
	if (err) {
		fi = get_fuse_inode(inode);
		rfuse_sync_release(fi, ff, flags);
	} else {
		file->private_data = ff;
		fuse_finish_open(inode, file);
	}

	rfuse_put_request(r_req);
	return err;

out_free_ff:
	fuse_file_free(ff);
out_err:
	rfuse_put_request(r_req);
out_put_forget_req:
	return err;
}


/************ 5. UNLINK  ************/

int rfuse_unlink(struct inode *dir, struct dentry *entry)
{
	int err;
	struct fuse_mount *fm = get_fuse_mount(dir);
	struct rfuse_req *r_req;
	struct rfuse_arg *in_arg;
	struct rfuse_iqueue *riq;
	unsigned int in_argument_index;


	if (fuse_is_bad(dir))
		return -EIO;

	r_req = rfuse_get_req(fm, false, false);
	riq = rfuse_get_specific_iqueue(fm->fc, r_req->riq_id);
	in_argument_index = rfuse_get_argument_buffer(fm, r_req->riq_id);
	in_arg = (struct rfuse_arg*)&riq->karg[in_argument_index]; // Argument

	r_req->in.opcode = FUSE_UNLINK;
	r_req->in.nodeid = get_node_id(dir);
		
	memcpy(in_arg, (char*)entry->d_name.name, entry->d_name.len + 1);
	r_req->in.arg[0] = in_argument_index;
	r_req->in.arglen[0] = entry->d_name.len + 1;
	
	err = rfuse_simple_request(r_req);

	if (!err) {
		struct inode *inode = d_inode(entry);
		struct fuse_inode *fi = get_fuse_inode(inode);

		spin_lock(&fi->lock);
		fi->attr_version = atomic64_inc_return(&fm->fc->attr_version);
		/*
		 * If i_nlink == 0 then unlink doesn't make sense, yet this can
		 * happen if userspace filesystem is careless.  It would be
		 * difficult to enforce correct nlink usage so just ignore this
		 * condition here
		 */
		if (inode->i_nlink > 0)
			drop_nlink(inode);
		spin_unlock(&fi->lock);
		fuse_invalidate_attr(inode);
		rfuse_dir_changed(dir);
		fuse_invalidate_entry_cache(entry);
		fuse_update_ctime(inode);
	} else if (err == -EINTR)
		rfuse_invalidate_entry(entry);
	
	rfuse_put_request(r_req);
	return err;
}

/************ 6. ACCESS  ************/

int rfuse_access(struct inode *inode, int mask)
{
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct fuse_access_in *inarg;
	struct rfuse_req *r_req;
	int err;
	
	BUG_ON(mask & MAY_NOT_BLOCK);

	if (fm->fc->no_access)
		return 0;

	r_req = rfuse_get_req(fm, false, false);
	inarg = (struct fuse_access_in*)(&r_req->args);
	
	inarg->mask = mask & (MAY_READ | MAY_WRITE | MAY_EXEC);
	r_req->in.opcode = FUSE_ACCESS;
	r_req->in.nodeid = get_node_id(inode);
//	r_req->in.arg[0] = inarg; //add
//	r_req->in.arglen[0] = sizeof(*inarg); //add

	err = rfuse_simple_request(r_req);

	if (err == -ENOSYS) {
		fm->fc->no_access = 1;
		err = 0;
	}
	rfuse_put_request(r_req);

	return err;
}

/************ 7. INODE  ************/

int rfuse_flush_times(struct inode *inode, struct fuse_file *ff)
{
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct fuse_setattr_in *inarg;
	struct fuse_attr_out outarg;
	struct rfuse_req *r_req;
	int res;

	r_req = rfuse_get_req(fm, false, false);
	inarg = (struct fuse_setattr_in*)(&r_req->args);

	memset(&outarg, 0, sizeof(outarg));

	inarg->valid = FATTR_MTIME;
	inarg->mtime = inode->i_mtime.tv_sec;
	inarg->mtimensec = inode->i_mtime.tv_nsec;
	if (fm->fc->minor >= 23) {
		inarg->valid |= FATTR_CTIME;
		inarg->ctime = inode->i_ctime.tv_sec;
		inarg->ctimensec = inode->i_ctime.tv_nsec;
	}
	if (ff) {
		inarg->valid |= FATTR_FH;
		inarg->fh = ff->fh;
	}
	r_req->in.opcode = FUSE_SETATTR;
	r_req->in.nodeid = get_node_id(inode);
	// fuse_setattr_fill(fm->fc, &args, inode, &inarg, &outarg);
	res = rfuse_simple_request(r_req);
	rfuse_put_request(r_req);

	return res;
}

/************ 8. RENAME  ************/
int rfuse_rename_common(struct inode *olddir, struct dentry *oldent,
			      struct inode *newdir, struct dentry *newent,
			      unsigned int flags, int opcode, size_t argsize)
{
	int err;
	struct fuse_rename2_in *inarg; 
	struct fuse_mount *fm = get_fuse_mount(olddir);
	struct rfuse_req *r_req;
	struct rfuse_arg *arg1;
	struct rfuse_arg *arg2;
	struct rfuse_iqueue *riq;
	unsigned int in_arg1_index;
	unsigned int in_arg2_index;

	r_req = rfuse_get_req(fm, false, false);
	riq = rfuse_get_specific_iqueue(fm->fc, r_req->riq_id);
	inarg = (struct fuse_rename2_in*)(&r_req->args); // Specific header

	in_arg1_index = rfuse_get_argument_buffer(fm, r_req->riq_id);
	in_arg2_index = rfuse_get_argument_buffer(fm, r_req->riq_id);
	arg1 = (struct rfuse_arg*)&riq->karg[in_arg1_index]; // Argument
	arg2 = (struct rfuse_arg*)&riq->karg[in_arg2_index]; // Argument

	inarg->newdir = get_node_id(newdir);
	inarg->flags = flags;

	r_req->in.opcode = opcode;
	r_req->in.nodeid = get_node_id(olddir);

	r_req->in.arg[0] = in_arg1_index;
	r_req->in.arglen[0] = oldent->d_name.len + 1;
	memcpy(arg1, (char*)oldent->d_name.name, oldent->d_name.len + 1);
	r_req->in.arg[1] = in_arg2_index;
	r_req->in.arglen[1] = newent->d_name.len + 1;
	memcpy(arg2, (char*)newent->d_name.name, newent->d_name.len + 1);

	err = rfuse_simple_request(r_req);
	if (!err) {
		/* ctime changes */
		fuse_invalidate_attr(d_inode(oldent));
		fuse_update_ctime(d_inode(oldent));

		if (flags & RENAME_EXCHANGE) {
			fuse_invalidate_attr(d_inode(newent));
			fuse_update_ctime(d_inode(newent));
		}

		rfuse_dir_changed(olddir);
		if (olddir != newdir)
			rfuse_dir_changed(newdir);

		/* newent will end up negative */
		if (!(flags & RENAME_EXCHANGE) && d_really_is_positive(newent)) {
			fuse_invalidate_attr(d_inode(newent));
			fuse_invalidate_entry_cache(newent);
			fuse_update_ctime(d_inode(newent));
		}
	} else if (err == -EINTR) {
		/* If request was interrupted, DEITY only knows if the
		   rename actually took place.  If the invalidation
		   fails (e.g. some process has CWD under the renamed
		   directory), then there can be inconsistency between
		   the dcache and the real filesystem.  Tough luck. */
		rfuse_invalidate_entry(oldent);
		if (d_really_is_positive(newent))
			rfuse_invalidate_entry(newent);
	}

	rfuse_put_request(r_req);

	return err;
}

/************ 9. LINK  ************/

int rfuse_symlink(struct user_namespace *mnt_userns, struct inode *dir,
			struct dentry *entry, const char *link)
{
	int err;
	struct fuse_mount *fm = get_fuse_mount(dir);
	unsigned len = strlen(link) + 1;
	struct rfuse_req *r_req;
	struct rfuse_arg* arg1;
	struct rfuse_arg* arg2;
	struct rfuse_iqueue *riq;
	unsigned int in_arg1_index;
	unsigned int in_arg2_index;

	r_req = rfuse_get_req(fm, false, false);
	riq = rfuse_get_specific_iqueue(fm->fc, r_req->riq_id);

	in_arg1_index = rfuse_get_argument_buffer(fm, r_req->riq_id);
	in_arg2_index = rfuse_get_argument_buffer(fm, r_req->riq_id);
	arg1 = (struct rfuse_arg*)&riq->karg[in_arg1_index]; // Argument
	arg2 = (struct rfuse_arg*)&riq->karg[in_arg2_index]; // Argument

	r_req->in.opcode = FUSE_SYMLINK;

	r_req->in.arg[0] = in_arg1_index;
	r_req->in.arglen[0] = entry->d_name.len + 1;
	memcpy(arg1, (char*)entry->d_name.name, entry->d_name.len + 1);
	r_req->in.arg[1] = in_arg2_index;
	r_req->in.arglen[1] = len;
	memcpy(arg2, (char*)link, len);

	err = rfuse_create_new_entry(fm, r_req, dir, entry, S_IFLNK);
	rfuse_put_request(r_req);
	return err;
}

int rfuse_link(struct dentry *entry, struct inode *newdir,
		     struct dentry *newent)
{
	int err;
	struct fuse_link_in *inarg;
	struct inode *inode = d_inode(entry);
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct rfuse_req *r_req;
	struct rfuse_arg* arg1;
	struct rfuse_iqueue *riq;
	unsigned int in_arg1_index;

	r_req = rfuse_get_req(fm, false, false);
	riq = rfuse_get_specific_iqueue(fm->fc, r_req->riq_id);
	inarg = (struct fuse_link_in *)(&r_req->args);
	in_arg1_index = rfuse_get_argument_buffer(fm, r_req->riq_id);
	arg1 = (struct rfuse_arg*)&riq->karg[in_arg1_index]; // Argument

	inarg->oldnodeid = get_node_id(inode);

	r_req->in.opcode = FUSE_LINK;

	r_req->in.arg[0] = in_arg1_index;
	r_req->in.arglen[0] = newent->d_name.len + 1;
	memcpy(arg1, (char*)newent->d_name.name, newent->d_name.len + 1);

	err = rfuse_create_new_entry(fm, r_req, newdir, newent, inode->i_mode);
	/* Contrary to "normal" filesystems it can happen that link
	   makes two "logical" inodes point to the same "physical"
	   inode.  We invalidate the attributes of the old one, so it
	   will reflect changes in the backing inode (link count,
	   etc.)
	*/
	if (!err) {
		struct fuse_inode *fi = get_fuse_inode(inode);

		spin_lock(&fi->lock);
		fi->attr_version = atomic64_inc_return(&fm->fc->attr_version);
		if (likely(inode->i_nlink < UINT_MAX))
			inc_nlink(inode);
		spin_unlock(&fi->lock);
		fuse_invalidate_attr(inode);
		fuse_update_ctime(inode);
	} else if (err == -EINTR) {
		fuse_invalidate_attr(inode);
	}

	rfuse_put_request(r_req);
	return err;
}

int rfuse_readlink_page(struct inode *inode, struct page *page)
{
	struct fuse_mount *fm = get_fuse_mount(inode);
	struct fuse_page_desc desc = { .length = PAGE_SIZE - 1 };
	struct rfuse_pages rp = {
		.num_pages = 1,
		.pages = &page,
		.descs = &desc,
	};
	char *link;
	ssize_t res;

	struct rfuse_req *r_req;
	r_req = rfuse_get_req(fm, false, false);	

	r_req->in.opcode = FUSE_READLINK;
	r_req->in.nodeid = get_node_id(inode);

	r_req->out_pages = true;
	r_req->out_argvar = true;
	r_req->page_zeroing = true;

	r_req->out.arglen = desc.length;
	r_req->rp = &rp;

	res = rfuse_simple_request(r_req);

	fuse_invalidate_atime(inode);

	if (res < 0)
		return res;

	if (WARN_ON(res >= PAGE_SIZE))
		return -EIO;

	link = page_address(page);
	link[res] = '\0';

	return 0;
}
