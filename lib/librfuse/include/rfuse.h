#ifndef R_FUSE_H_
#define R_FUSE_H_

#ifndef FUSE_USE_VERSION
#error FUSE_USE_VERSION not defined
#endif

#include "fuse_common.h"

#include <stdint.h>
#include <utime.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/uio.h>
#include <unistd.h>
#include <semaphore.h>



#ifdef __cplusplus
#include <atomic>
using namespace std;
#else
#include <stdatomic.h>
#endif

enum fuse_req_flag {
	FR_ISREPLY,
	FR_FORCE,
	FR_BACKGROUND,
	FR_WAITING,
	FR_ABORTED,
	FR_INTERRUPTED,
	FR_LOCKED,
	FR_PENDING,
	FR_SENT,
	FR_FINISHED,
	FR_PRIVATE,
	FR_ASYNC,
	FR_NEEDWAKEUP,
};

#define SET_BIT(x, pos) (x |= (1U << pos))
#define CLEAR_BIT(x, pos) (x &= (~(1U << pos)))
#define TEST_BIT(x, pos) (x & (1UL << pos) )

/**
 * The following MACROs are used in "liburing/src/include/liburing/barrier.h"
 * The io_uring 'modifies' the ring buffers 'head' in the user space and 
 * 'Checks' the ring buffer's 'tail'... Such sequence should accompany a 'memory barrier'
 * Okay, so I originally wanted to add it by my taste. But, it was almost impossible to 
 * check whether I have implemented correctly. So, I just followed the basic sequence of io_uring
 * using the bellow MACROs in user space would provide memory barriers (at least)equal to io_uring, which is
 * a well known shared memory ring buffer.
 */

#ifdef __cplusplus
#include <atomic>

template <typename T>
static inline void RFUSE_WRITE_ONCE(T &var, T val)
{
    std::atomic_store_explicit(reinterpret_cast<std::atomic<T> *>(&var),
                   val, std::memory_order_relaxed);
}
template <typename T>
static inline T RFUSE_READ_ONCE(const T &var)
{
    return std::atomic_load_explicit(
        reinterpret_cast<const std::atomic<T> *>(&var),
        std::memory_order_relaxed);
}

template <typename T>
static inline void rfuse_smp_store_release(T *p, T v)
{
    std::atomic_store_explicit(reinterpret_cast<std::atomic<T> *>(p), v,
                   std::memory_order_release);
}

template <typename T>
static inline T rfuse_smp_load_acquire(const T *p) 
{
    return std::atomic_load_explicit(
        reinterpret_cast<const std::atomic<T> *>(p),
        std::memory_order_acquire);
}

static inline void rfuse_smp_mb()
{
    std::atomic_thread_fence(std::memory_order_seq_cst);
}
#else
#include <stdatomic.h>

#define RFUSE_WRITE_ONCE(var, val) \
		atomic_store_explicit((_Atomic __typeof__(var) *)&(var), \
		(val), memory_order_relaxed)
#define RFUSE_READ_ONCE(var) \
		atomic_load_explicit((_Atomic __typeof__(var) *)&(var),	\
		memory_order_relaxed)

#define rfuse_smp_store_release(p, v) \
		atomic_store_explicit((_Atomic __typeof__(*(p)) *)(p), \
		(v), memory_order_release)
#define rfuse_smp_load_acquire(p) \
		atomic_load_explicit((_Atomic __typeof__(*(p)) *)(p), memory_order_acquire)

#define rfuse_smp_mb() atomic_thread_fence(memory_order_seq_cst)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define RFUSE_WAKE_UP_COMP 			37
#define RFUSE_REPLY_ASYNC		 	38
#define RFUSE_DAEMON_SLEEP 			39

// state for recognizing whether the completion thread is woken up by user request
#define COMP_NEED_WAKEUP_FROM_USER  (1U << 3)
#define COMP_ALL_COMP_WORKING 	    (1U << 4)

#define RFUSE_NUM_IQUEUE 		80	
#define RFUSE_MAX_QUEUE_SIZE 		1024*4	
#define RFUSE_WORKER_PER_RING		2

#define RFUSE_RIQ_ID_MASK       	0x00ff0000ULL
#define RFUSE_QUEUE_MAP_MASK    	0xff000000ULL
#define RFUSE_REQ_IDX_MASK      	0x0000ffff00000000ULL

#define RFUSE_IQUEUE				0ULL
#define RFUSE_PENDING				0x08000000ULL
#define RFUSE_INTERRUPT				0x18000000ULL
#define RFUSE_FORGET				0x20000000ULL
#define RFUSE_COMPLETE				0x28000000ULL
#define RFUSE_ARG               	0x30000000ULL
#define RFUSE_REQ					0x38000000ULL
#define RFUSE_READ					0x40000000ULL
#define RFUSE_WRITE					0x48000000ULL

struct rfuse_req{
	/** Request input header **/
	struct{
		uint64_t    unique;
		uint64_t    nodeid;
		uint32_t    opcode;
		uint32_t    uid;
		uint32_t    gid;
		uint32_t    pid;
		uint32_t	arg[2];	// Location of in argument
		uint32_t	arglen[2];	// Size of in argument
	}in; // 48 

	/** Request output header **/
	struct{
		int32_t     error;
		uint32_t	arg;	// Location of out argument
		uint32_t	arglen;	// Size of out argument
		uint32_t	padding;	
	}out; // 16

	/** request buffer index **/
	uint32_t index; // 4
	int32_t riq_id;

	/** Request flags, updated with test/set/clear_bit() **/
	unsigned long flags; // 8

	/** refcount **/
	int no_touch_1; // 4

	/** fuse_mount this request belongs to **/
	int *no_touch_2; // 8

	/** Used to wake up the task waiting for completion of request **/
	char no_touch_3[24];

	struct{
		uint8_t argument_space[120];
	}args; // 120
	
	uint64_t padding[2];
};

struct rfuse_interrupt_entry{
	uint64_t    unique;
};

struct rfuse_forget_entry{
	uint64_t	unique;
	uint64_t    nlookup;
	uint64_t    nodeid;
	uint64_t	padding;
};

struct rfuse_address_entry{ 
	uint32_t request;
}; // 4 bytes

// Pending queue, Complete queue 
struct ring_buffer_1{
	uint32_t tail;
	uint32_t head;
	uint32_t mask;
	uint32_t entries;

	struct rfuse_address_entry *kaddr; // kernel address
	struct rfuse_address_entry *uaddr; // user address
};

// Interrupt queue
struct ring_buffer_2{
	uint32_t head;
	uint32_t tail;
	uint32_t mask;
	uint32_t entries;

	struct rfuse_interrupt_entry *kaddr; // kernel address
	struct rfuse_interrupt_entry *uaddr; // user address
};

// Forget queue
struct ring_buffer_3{
	uint32_t head;
	uint32_t tail;
	uint32_t mask;
	uint32_t entries;

	struct rfuse_forget_entry *kaddr; // kernel address
	struct rfuse_forget_entry *uaddr; // user address
};

struct rfuse_arg{
	uint8_t garbage[256];
};

/**
  mmap the total rfuse_iqueue to fuse daemon
 **/
struct rfuse_iqueue{
	int riq_id;
	/** Pending queue **/
	struct ring_buffer_1 pending;
	/** Interrupt queue **/
	struct ring_buffer_2 interrupts;
	/** Forget queue **/
	struct ring_buffer_3 forgets;
	/** Complete queue **/
	struct ring_buffer_1 completes;

	/** Dyanmic argument space **/
	struct rfuse_arg *uarg; // user address
	struct rfuse_arg *karg; // kernel address
	struct rfuse_req *ureq;
	struct rfuse_req *kreq;
	
	/** unused **/
	const unsigned connected;
	const int garbage;
	const uint64_t reqctr;
	const void *priv;
	const struct{
		unsigned long bitmap_size;
		unsigned long *bitmap;
	}argbm;
	const struct{
		unsigned long bitmap_size;
		unsigned long *bitmap;
	}reqbm;
};

struct rfuse_loop_args{
	struct fuse_session *se;
	struct fuse_loop_config *config;
	int riq_id;
};

struct rfuse_main_worker {
	pthread_t main_thread_id;
	struct rfuse_loop_args args;
};

struct rfuse_worker {
	struct rfuse_worker *prev;
	struct rfuse_worker *next;
	pthread_t thread_id;

	// We need to include fuse_buf so that we can properly free
	// it when a thread is terminated by pthread_cancel().
	// Normal I/O: buffer for write/read syscall 
	// Splice I/O: metadata for data in pipe
	struct fuse_buf fbuf;
	struct fuse_chan *ch;
	struct rfuse_mt *mt;
};

struct rfuse_mt {
	pthread_mutex_t lock;
	int numworker;
	int numavail;
	struct fuse_session *se;
	struct rfuse_worker main;
	sem_t finish;
	int exit;
	int error;
	int clone_fd;
	int max_idle;
	int riq_id;
};
// ******************************* rfuse_lowlevel.c Operations ******************************* //
/**
 * @brief Read pending queue's head 
 * 
 * @param riq 
 * @return struct rfuse_pending_entry* 
 */
struct rfuse_address_entry *rfuse_read_pending_head(struct rfuse_iqueue *riq);

/**
 * @brief Extract the pending queue's head
 * 
 * @param riq 
 */
void rfuse_extract_pending_head(struct rfuse_iqueue *riq);

/**
 * @brief Read Forget queue's head
 * 
 * @param riq 
 * @return struct rfuse_forget_entry* 
 */
struct rfuse_forget_entry *rfuse_read_forgets_head(struct rfuse_iqueue *riq);

/**
 * @brief Extract the forget queue's head
 * 
 * @param riq 
 */
void rfuse_extract_forgets_head(struct rfuse_iqueue *riq);

/**
 * @brief Read cmoplete queue's Tail
 * 
 * @param riq 
 * @return struct rfuse_complete_entry* 
 */
struct rfuse_address_entry *rfuse_read_completes_tail(struct rfuse_iqueue *riq);


/**
 * @brief commit the complete queue's tail
 * 
 * @param riq 
 */
void rfuse_submit_completes_tail(struct rfuse_iqueue *riq); 

/**
 * @brief Initialize a user level request(ULR)'s list
 * 
 * @param req 
 */
void rfuse_list_init_req(struct rfuse_user_req *req);

/**
 * @brief Extract a ULR from the ULR list
 * 
 * @param req 
 */
void rfuse_list_del_req(struct rfuse_user_req *req);

/**
 * @brief Allocate a new ULR
 * 
 * @param se 
 * @return struct rfuse_user_req* 
 */
struct rfuse_user_req *rfuse_ll_alloc_req(struct fuse_session *se, int riq_id);

/**
 * @brief Destroy a ULR
 * 
 * @param req 
 */
void rfuse_free_req(fuse_req_t req);


/**
 * @brief Reply an error to the Fuse Kernel Module
 * 
 * @param u_req 
 * @param err 
 * @return int 
 */
int fuse_reply_err(fuse_req_t u_req, int err);

int fuse_reply_buf(fuse_req_t u_req, const char *buf, size_t size);

int fuse_reply_attr(fuse_req_t req, const struct stat *attr, double attr_timeout);

int fuse_reply_statfs(fuse_req_t req, const struct statvfs *stbuf);

int fuse_reply_entry(fuse_req_t req, const struct fuse_entry_param *e);

int fuse_reply_create(fuse_req_t u_req, const struct fuse_entry_param *e, const struct fuse_file_info *f);

void fuse_reply_none(fuse_req_t u_req);

int fuse_reply_open(fuse_req_t u_req, const struct fuse_file_info *f);

int fuse_reply_write(fuse_req_t u_req, size_t count);

int fuse_reply_data(fuse_req_t u_req, struct fuse_bufvec *bufv, enum fuse_buf_copy_flags flags);

int fuse_reply_readlink(fuse_req_t req, const char *link);

int fuse_reply_xattr(fuse_req_t req, size_t count);

int fuse_reply_lock(fuse_req_t req, const struct flock *lock);

int fuse_reply_bmap(fuse_req_t req, uint64_t idx);

int fuse_reply_ioctl(fuse_req_t req, int result, const void *buf, size_t size);

int fuse_reply_lseek(fuse_req_t req, off_t off);

int fuse_reply_poll(fuse_req_t req, unsigned revents);

void *fuse_req_userdata(fuse_req_t req);

const struct fuse_ctx *fuse_req_ctx(fuse_req_t req);

int fuse_req_getgroups(fuse_req_t req, int size, gid_t list[]);

/**
 * This description is about old_fuse_session_loop...
 * 
 * Enter a single threaded, blocking event loop.
 *
 * When the event loop terminates because the connection to the FUSE
 * kernel module has been closed, this function returns zero. This
 * happens when the filesystem is unmounted regularly (by the
 * filesystem owner or root running the umount(8) or fusermount(1)
 * command), or if connection is explicitly severed by writing ``1``
 * to the``abort`` file in ``/sys/fs/fuse/connections/NNN``. The only
 * way to distinguish between these two conditions is to check if the
 * filesystem is still mounted after the session loop returns.
 *
 * When some error occurs during request processing, the function
 * returns a negated errno(3) value.
 *
 * If the loop has been terminated because of a signal handler
 * installed by fuse_set_signal_handlers(), this function returns the
 * (positive) signal value that triggered the exit.
 *
 * @param se the session
 * @return 0, -errno, or a signal value
 */
int fuse_session_loop(struct fuse_session *se);
void *rfuse_session_loop_mt_mriq(void *data);
int fuse_session_loop_mt_31(struct fuse_session *se, int clone_fd);
int fuse_session_loop_mt_32(struct fuse_session *se, struct fuse_loop_config *config);

#ifdef __cplusplus
}
#endif

#endif   /* RFUSE_H_ */
