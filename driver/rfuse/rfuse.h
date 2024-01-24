#ifndef _FS_RFUSE_H
#define _FS_RFUSE_H

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/fuse.h>
#include <linux/mount.h>
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
 
#include "rfuse_comp.h"

#define RFUSE_NUM_IQUEUE     80           // Number of rfuse iqueue
#define RFUSE_MAX_QUEUE_SIZE 1024*4      // Maximum number of requests in a queue

#define RFUSE_RIQ_ID_MASK    0x00ff0000ULL
#define RFUSE_QUEUE_MAP_MASK 0xff000000ULL
#define RFUSE_REQ_IDX_MASK   0x0000ffff00000000ULL

#define RFUSE_IQUEUE         0ULL
#define RFUSE_PENDING        0x08000000ULL
#define RFUSE_INTERRUPT      0x18000000ULL
#define RFUSE_FORGET         0x20000000ULL
#define RFUSE_COMPLETE       0x28000000ULL
#define RFUSE_ARG	     0x30000000ULL
#define RFUSE_REQ	     0x38000000ULL
#define RFUSE_READ	     0x40000000ULL
#define RFUSE_WRITE	     0x48000000ULL

struct rfuse_req{
	/** Request input header **/
	struct{
		uint64_t    unique;
		uint64_t    nodeid;
		uint32_t    opcode;
		uint32_t    uid;
		uint32_t    gid;
		uint32_t    pid;
		uint32_t	arg[2];	    // Location of in operation-specific argument
		uint32_t	arglen[2];	// Size of in operation-specific argument
	}in; // 48 

	/** Request output header **/
	struct{
		int32_t     error;
		uint32_t	arg;	// Location of out operation-specific argument
		uint32_t	arglen;	// Size of out operation-specific argument
		uint32_t	padding;	
	}out; // 16

	/** request buffer index **/
	uint32_t index; // 4
	int32_t riq_id;
	/** Request flags, updated with test/set/clear_bit() **/
	unsigned long flags; // 8

	/** fuse_mount this request belongs to **/
	struct fuse_mount *fm; // 8
	/** refcount **/
	refcount_t count; // 4
	/** Used to wake up the task waiting for completion of request **/
	wait_queue_head_t waitq; // 24

	struct{
		uint8_t argument_space[112];
	}args; // 112

	bool force:1;
	bool noreply:1;
	bool nocreds:1;
	bool in_pages:1;
	bool out_pages:1;
	bool out_argvar:1;
	bool page_zeroing:1;
	bool page_replace:1;
	bool may_block:1;

	struct rfuse_pages *rp;
	void (*end)(struct fuse_mount *fm, struct rfuse_req *r_req, int error);
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

struct rfuse_bg_entry{
	struct list_head list;
	uint32_t request;
	int32_t riq_id;
};

// Pending queue, Complete Queue
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

	/** Dyanmic argument buffer **/
	struct rfuse_arg *uarg; // user address
	struct rfuse_arg *karg; // kernel address

	/** Dynamic request buffer **/
	struct rfuse_req *ureq;	// user address
	struct rfuse_req *kreq; // kernel address

	/** Connection established **/
	unsigned connected;

	/** wait queue for requests to wait to receive a request buffer **/
	wait_queue_head_t waitq;

	/** Lock protecting accesses to members of this structure **/
	spinlock_t lock;

	/** The next unique request id **/
	u64 reqctr;

	/** Device specific state */
	void *priv;

	struct {
		unsigned long bitmap_size;
		unsigned full;
		unsigned long *bitmap;
	}argbm;

	struct {
		unsigned long bitmap_size;
		unsigned full;
		unsigned long *bitmap;
	}reqbm;

	wait_queue_head_t idle_user_waitq;

	/** synchronous request congestion control */
	int num_sync_sleeping;

	/** background request congestion control */
	struct list_head bg_queue; 
	spinlock_t bg_lock;

	unsigned max_background;
	unsigned congestion_threshold;
	unsigned num_background;
	unsigned active_background;
	int blocked;

	/** waitq for congested asynchronous requests*/
	wait_queue_head_t blocked_waitq;
};

#endif
