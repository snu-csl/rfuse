#ifndef _FS_RFUSE_COMP_H
#define _FS_RFUSE_COMP_H

#include <linux/fuse.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>

#define RFUSE_MAX_COMP 				1             // Maximum number of completion threads
#define RFUSE_COMP_MAX_IDLE 		50     // Maximum idle time of completion thread
#define RFUSE_WAKE_UP_COMP			37 
#define RFUSE_REPLY_ASYNC		 	38 
#define RFUSE_DAEMON_SLEEP			39 

// completion thread must only be set to one of the following states
#define COMP_NEED_WAKEUP 			(1U << 0)
#define COMP_SLEEPING    			(1U << 1)
#define COMP_WORKING     			(1U << 2)

// state for recognizing whether the completion thread is woken up by user request
#define COMP_NEED_WAKEUP_FROM_USER  (1U << 3)
#define COMP_ALL_COMP_WORKING 	    (1U << 4)

struct rfuse_iqueue; // forward declaration
struct rfuse_req; // Forward declaration
struct fuse_conn; // Forward declaration

struct rfuse_comp_entry {
	int comp_id;
    u32 comp_state;
	struct task_struct *comp_kthread;

	struct list_head list;
};

struct rfuse_comp_head {
	spinlock_t lock;
	struct list_head list;
};

struct rfuse_comp_args {
	struct fuse_conn *fc;
	int riq_id;
	int comp_id;
	struct rfuse_comp_entry *entry;
};

// For synchronous request completion
void rfuse_sleep_comp(struct fuse_conn *fc, struct rfuse_iqueue *riq, struct rfuse_req *r_req);
int rfuse_completion_poll(struct fuse_conn *fc, struct rfuse_iqueue *riq, struct rfuse_req *r_req);


#endif
