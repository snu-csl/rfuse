/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU LGPLv2.
  See the file COPYING.LIB
*/

#include "fuse.h"
#include "fuse_lowlevel.h"
#include "rfuse.h"

struct mount_opts;

/**
  Structure containing user specific data about a request.
  - mutext lock
  - interrupted flag
  - kept as a linked list to search through during interrupt check
 **/
struct rfuse_user_req{
	struct fuse_session *se;
	int ctr;
	struct fuse_ctx ctx;
	uint64_t unique; // It's not necessary, but for forget requests
	uint64_t nlookup; // Used only for forget requests
	uint32_t index; // index of "rfuse_req" in request buffer
	pthread_mutex_t lock;
	struct fuse_chan *ch;
	int interrupted;
	unsigned int ioctl_64bit : 1;
	union {
		struct {
			uint64_t unique;
		} i;
		struct {
			fuse_interrupt_func_t func;
			void *data;
		} ni; 
	} u;
	// All rfuse_user_req should know about where the kernel fuse request came from 
	int riq_id;
	struct rfuse_iqueue *riq;
	struct rfuse_user_req *next;
	struct rfuse_user_req *prev;
	struct rfuse_worker *w;
};


struct fuse_req {
	struct fuse_session *se;
	uint64_t unique;
	int ctr;
	pthread_mutex_t lock;
	struct fuse_ctx ctx;
	struct fuse_chan *ch;
	int interrupted;
	unsigned int ioctl_64bit : 1;
	union {
		struct {
			uint64_t unique;
		} i;
		struct {
			old_fuse_interrupt_func_t func;
			void *data;
		} ni;
	} u;
	struct fuse_req *next;
	struct fuse_req *prev;
};

struct fuse_notify_req {
	uint64_t unique;
	void (*reply)(struct fuse_notify_req *, old_fuse_req_t, fuse_ino_t,
		      const void *, const struct fuse_buf *);
	struct fuse_notify_req *next;
	struct fuse_notify_req *prev;
};

struct fuse_session {
	char *mountpoint;
	volatile int exited;
	int fd;
	// multiple rfuse iqueues (NUM_RFUSE_IQUEUE)
	struct rfuse_iqueue **riq; 
	struct mount_opts *mo;
	int debug;
	int deny_others;
	struct fuse_lowlevel_ops op;
	int got_init;
	struct cuse_data *cuse_data;
	void *userdata;
	uid_t owner;
	struct fuse_conn_info conn;
	struct fuse_req list;
	// multiple ureq list corresponding to multiple rfuse iqueues
	struct rfuse_user_req *rfuse_list;
	struct fuse_req interrupts;
	// struct rfuse_user_req interrupts;
	pthread_mutex_t lock;
	pthread_mutex_t *riq_lock;
	int got_destroy;
	pthread_key_t pipe_key;
	int broken_splice_nonblock;
	uint64_t notify_ctr;
	struct fuse_notify_req notify_list;
	size_t bufsize;
	int error;
};

struct fuse_chan {
	pthread_mutex_t lock;
	int ctr;
	int fd;
};

/**
 * Filesystem module
 *
 * Filesystem modules are registered with the FUSE_REGISTER_MODULE()
 * macro.
 *
 */
struct fuse_module {
	char *name;
	fuse_module_factory_t factory;
	struct fuse_module *next;
	struct fusemod_so *so;
	int ctr;
};

/* ----------------------------------------------------------- *
 * Channel interface (when using -o clone_fd)		       *
 * ----------------------------------------------------------- */

/**
 * Obtain counted reference to the channel
 *
 * @param ch the channel
 * @return the channel
 */
struct fuse_chan *fuse_chan_get(struct fuse_chan *ch);

/**
 * Drop counted reference to a channel
 *
 * @param ch the channel
 */
void fuse_chan_put(struct fuse_chan *ch);

struct mount_opts *parse_mount_opts(struct fuse_args *args);
void destroy_mount_opts(struct mount_opts *mo);
void fuse_mount_version(void);
unsigned get_max_read(struct mount_opts *o);
void fuse_kern_unmount(const char *mountpoint, int fd);
int fuse_kern_mount(const char *mountpoint, struct mount_opts *mo);

int fuse_send_reply_iov_nofree(old_fuse_req_t req, int error, struct iovec *iov,
			       int count);
void fuse_free_req(old_fuse_req_t req);

void cuse_lowlevel_init(old_fuse_req_t req, fuse_ino_t nodeide, const void *inarg);

int fuse_start_thread(pthread_t *thread_id, void *(*func)(void *), void *arg);

int fuse_session_receive_buf_int(struct fuse_session *se, struct fuse_buf *buf,
				 struct fuse_chan *ch);
void fuse_session_process_buf_int(struct fuse_session *se,
				  const struct fuse_buf *buf, struct fuse_chan *ch);

struct fuse *fuse_new_31(struct fuse_args *args, const struct fuse_operations *op,
		      size_t op_size, void *private_data);
int fuse_loop_mt_32(struct fuse *f, struct fuse_loop_config *config);
int old_fuse_session_loop_mt_32(struct fuse_session *se, struct fuse_loop_config *config);


// RFUSE
bool rfuse_read_queue(struct rfuse_worker *w, struct rfuse_mt *mt, struct fuse_chan *ch, int forget);

struct fuse_chan *rfuse_chan_get(struct fuse_chan *ch);
void rfuse_chan_put(struct fuse_chan *ch);
int rfuse_start_thread(pthread_t *thread_id, void *(*func)(void *), void *arg);
int rfuse_loop_start_thread(struct rfuse_mt *mt);

#define FUSE_MAX_MAX_PAGES 256
#define FUSE_DEFAULT_MAX_PAGES_PER_REQ 32

/* room needed in buffer to accommodate header */
#define FUSE_BUFFER_HEADER_SIZE 0x1000

