#include "fuse_i.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/sched/signal.h>
#include <linux/uio.h>
#include <linux/miscdevice.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/pipe_fs_i.h>
#include <linux/swap.h>
#include <linux/splice.h>
#include <linux/sched.h>
#include <linux/random.h>
#include <asm/atomic.h>

#include <linux/ktime.h>
#include <linux/time.h>
#include <linux/timekeeping.h>

#define RFUSE_INT_REQ_BIT (1ULL << 0)
#define RFUSE_REQ_ID_STEP (1ULL << 1)
/*
   0: Round Robin 
   1: ThreadID moduler
   2: Application CPU ID
 */

#define RFUSE_SELECTION_ALGO 2
atomic_t rr_id = ATOMIC_INIT(0);

/* -1: (App) user syscall start 
   0: request opcode (exception, not timestamps) 
   1: enqueue complet, wait start
   2: (librfuse) rfuse daemon dequeued a request 
   3: (userfs) ops start
   4: (userkfs) ops end
   5: (librfuse) rfuse daemon enqueued a reply 
   6: comp thread dequeued a reply   
   7: wake up app thread
   8: (App) user syscall end
*/

static u64 timestamps[9] = {0, };
#ifdef DEBUG
	#define GET_TIMESTAMPS(i) timestamps[i] = ktime_get_real_ns(); 
#else 
	#define GET_TIMESTAMPS(i) ;
#endif

/*
* Duplicated function from dev.c
*/
static struct fuse_dev *fuse_get_dev(struct file *file)
{
	return READ_ONCE(file->private_data);
}


/************ 0. Copy of original fuse functions ************/
static void rfuse_drop_waiting(struct fuse_conn *fc)
{
	/*
	 * lockess check of fc->connected is okay, because atomic_dec_and_test()
	 * provides a memory barrier matched with the one in fuse_wait_aborted()
	 * to ensure no wake-up is missed.
	 */
	if (atomic_dec_and_test(&fc->num_waiting) &&
			!READ_ONCE(fc->connected)) {
		/* wake up aborters */
		wake_up_all(&fc->blocked_waitq);
	}
}

static bool rfuse_block_alloc(struct fuse_conn *fc, bool for_background, int riq_id)
{
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(fc, riq_id);
	return !fc->initialized || (for_background && riq->blocked);
}

// Get a unique request number 
// This should be called with the riq lock aquired
u64 rfuse_get_unique(struct rfuse_iqueue *riq){ 
	riq->reqctr += RFUSE_REQ_ID_STEP;
	return riq->reqctr;
}

static void rfuse_force_creds(struct rfuse_req *r_req){
	struct fuse_conn *fc = r_req->fm->fc;

	r_req->in.uid = from_kuid(fc->user_ns, current_fsuid());
    r_req->in.gid = from_kgid(fc->user_ns, current_fsgid());
    r_req->in.pid = pid_nr_ns(task_pid(current), fc->pid_ns);

}

static int rfuse_check_page(struct page *page)
{
	if (page_mapcount(page) ||
			page->mapping != NULL ||
			(page->flags & PAGE_FLAGS_CHECK_AT_PREP &
			 ~(1 << PG_locked |
				 1 << PG_referenced |
				 1 << PG_uptodate |
				 1 << PG_lru |
				 1 << PG_active |
				 1 << PG_workingset |
				 1 << PG_reclaim |
				 1 << PG_waiters))) {
		dump_page(page, "fuse: trying to steal weird page");
		return 1;
	}
	return 0;
}



/************ 1. Mmap ************/

void rfuse_init_ring_buffer_1(struct ring_buffer_1 *rb){
	rb->tail=0;
	rb->head=0;
	rb->mask = RFUSE_MAX_QUEUE_SIZE-1;
	rb->entries= RFUSE_MAX_QUEUE_SIZE;
}
void rfuse_init_ring_buffer_2(struct ring_buffer_2 *rb){
	rb->head=0;
	rb->tail=0;
	rb->mask = RFUSE_MAX_QUEUE_SIZE-1;
	rb->entries= RFUSE_MAX_QUEUE_SIZE;
}
void rfuse_init_ring_buffer_3(struct ring_buffer_3 *rb){
	rb->head=0;
    rb->tail=0;
    rb->mask = RFUSE_MAX_QUEUE_SIZE-1;
    rb->entries= RFUSE_MAX_QUEUE_SIZE;
}	

void rfuse_iqueue_init(struct fuse_conn *fc, void *priv){
	int i = 0;	
	struct rfuse_iqueue **riq;
	int node_id = 0;

	// init rfuse iqueue
	riq = kzalloc(sizeof(struct rfuse_iqueue *) * RFUSE_NUM_IQUEUE, GFP_KERNEL);
	for(i = 0; i < RFUSE_NUM_IQUEUE; i++){
		printk("Initialize rfuse iqueue, id: %d\n", i);
		if (!cpu_online(i) || !cpu_present(i)) {
        		pr_err("Invalid CPU %d\n", i);
    		}
		node_id = cpu_to_node(i);

		riq[i] = kzalloc_node(4096, GFP_KERNEL, node_id);

		spin_lock_init(&riq[i]->lock);
		riq[i]->riq_id = i;
		init_waitqueue_head(&riq[i]->waitq);
		init_waitqueue_head(&riq[i]->idle_user_waitq);
		riq[i]->connected=1;
		riq[i]->priv=priv;
	
		// init ring buffer
		rfuse_init_ring_buffer_1(&riq[i]->pending);
		rfuse_init_ring_buffer_2(&riq[i]->interrupts);
		rfuse_init_ring_buffer_3(&riq[i]->forgets);
		rfuse_init_ring_buffer_1(&riq[i]->completes);
	
		// allocate space for mmap
		riq[i]->pending.kaddr = kmalloc_node(sizeof(struct rfuse_address_entry) * RFUSE_MAX_QUEUE_SIZE, GFP_KERNEL, node_id);
		riq[i]->interrupts.kaddr = kmalloc_node(sizeof(struct rfuse_interrupt_entry) * RFUSE_MAX_QUEUE_SIZE, GFP_KERNEL, node_id);
		riq[i]->forgets.kaddr = kmalloc_node(sizeof(struct rfuse_forget_entry) * RFUSE_MAX_QUEUE_SIZE, GFP_KERNEL, node_id);
		riq[i]->completes.kaddr = kmalloc_node(sizeof(struct rfuse_address_entry) * RFUSE_MAX_QUEUE_SIZE, GFP_KERNEL, node_id);
		riq[i]->karg = kmalloc_node(sizeof(struct rfuse_arg)*RFUSE_MAX_QUEUE_SIZE * 2, GFP_KERNEL, node_id);
		riq[i]->kreq = kmalloc_node(sizeof(struct rfuse_req)*RFUSE_MAX_QUEUE_SIZE * 2, GFP_KERNEL, node_id);
	
		// init bitmaps
		riq[i]->argbm.bitmap_size = RFUSE_MAX_QUEUE_SIZE * 2;
		riq[i]->reqbm.bitmap_size = RFUSE_MAX_QUEUE_SIZE * 2;
		riq[i]->reqbm.full=0;
		riq[i]->argbm.full=0;
		riq[i]->argbm.bitmap = kzalloc_node((RFUSE_MAX_QUEUE_SIZE*2)>>3, GFP_KERNEL, node_id);
		riq[i]->reqbm.bitmap = kzalloc_node((RFUSE_MAX_QUEUE_SIZE*2)>>3, GFP_KERNEL, node_id);

		// init background queue
		INIT_LIST_HEAD(&riq[i]->bg_queue);
		spin_lock_init(&riq[i]->bg_lock);
		init_waitqueue_head(&riq[i]->blocked_waitq);

		riq[i]->max_background = FUSE_DEFAULT_MAX_BACKGROUND;
		riq[i]->congestion_threshold = FUSE_DEFAULT_CONGESTION_THRESHOLD;
		riq[i]->num_background = 0;
		riq[i]->active_background = 0;

		riq[i]->num_sync_sleeping = 0;
	}

	fc->riq = riq;
}

void rfuse_iqueue_release(struct fuse_conn *fc){
	int i = 0;
	struct rfuse_iqueue **riq = fc->riq;
	
	for(i = 0; i < RFUSE_NUM_IQUEUE; i++) {
		kfree(riq[i]->pending.kaddr);
		kfree(riq[i]->interrupts.kaddr);
		kfree(riq[i]->forgets.kaddr);
		kfree(riq[i]->completes.kaddr);
		kfree(riq[i]->karg);
		kfree(riq[i]->kreq);
	
		kfree(riq[i]->argbm.bitmap);
		kfree(riq[i]->reqbm.bitmap);
	}

	kfree(riq);
}
/* for I/O mmap pages*/
int rfuse_io_mmap(struct vm_area_struct *vma, struct fuse_dev *fud, int req_index, int riq_id, unsigned nbytes){
	struct rfuse_pages *rp;
	struct rfuse_req *r_req = &fud->fc->riq[riq_id]->kreq[req_index];
	unsigned long addr = vma->vm_start;
	unsigned int i;
	
	rp = r_req->rp;
	for(i = 0;i < rp->num_pages && nbytes; i++){
		struct page *page = rp->pages[i];
		unsigned long size = (unsigned long)min(nbytes, rp->descs[i].length);
		unsigned int offset = rp->descs[i].offset;
		
		void *mapaddr = kmap_atomic(page);
		void *buf = mapaddr + offset;
		unsigned long pfn = virt_to_phys(buf) >> PAGE_SHIFT;
		
		if(remap_pfn_range(vma, addr, pfn, size, vma->vm_page_prot)) {
			printk("RFUSE : io_mmap, remap_pfn_range failed, pfn: %lu\n", pfn);
			return 1;
		}

		kunmap_atomic(mapaddr);
		addr += size;
	}

	return 0;
}
/* do this across all riqs */
void *rfuse_validate_mmap_request(struct fuse_dev *fud, loff_t pgoff, size_t size){
	struct page *page;
	void *ptr;

	/* riq_id should be passed by the mmap offset argument */
	unsigned long long map_args = pgoff << PAGE_SHIFT;
	loff_t map_queue = map_args & RFUSE_QUEUE_MAP_MASK;
	int riq_id = (int)((map_args & RFUSE_RIQ_ID_MASK) >> 16);

	switch(map_queue){
		case RFUSE_IQUEUE:
			printk("map_queue, riq_id: %d\n", riq_id);
			ptr = (fud->fc->riq[riq_id]);
			break;
		case RFUSE_PENDING:
			ptr = fud->fc->riq[riq_id]->pending.kaddr;
			break;
		case RFUSE_INTERRUPT:
			ptr = fud->fc->riq[riq_id]->interrupts.kaddr;
			break;
		case RFUSE_FORGET:
			ptr = fud->fc->riq[riq_id]->forgets.kaddr;
			break;
		case RFUSE_COMPLETE:
			ptr = fud->fc->riq[riq_id]->completes.kaddr;
			break;
		case RFUSE_ARG:
			ptr = fud->fc->riq[riq_id]->karg;
			break;
		case RFUSE_REQ:
			ptr = fud->fc->riq[riq_id]->kreq;
			break;
		default:
			printk("Invalid map_queue argument\n");
			return ERR_PTR(-EINVAL);
	}

	// Check if the virtual memory space is big enough
	page = virt_to_head_page(ptr);
	if(size > page_size(page))
		return ERR_PTR(-EINVAL);

	return ptr;
}

/************ 2. Ring buffer ************/

static int select_round_robin(struct fuse_conn *fc){
	int ret;

	spin_lock(&fc->lock);

	if(atomic_read(&rr_id) == RFUSE_NUM_IQUEUE) 
		atomic_set(&rr_id, 0);

	ret = atomic_read(&rr_id);
	atomic_add(1, &rr_id);
	spin_unlock(&fc->lock);

	return ret;
}

static int select_thread_id(void){
	int ret = current->pid;
	
	return (ret % RFUSE_NUM_IQUEUE);
}

static int select_cpu_id(void){
	int ret = task_cpu(current);
	
	return (ret % RFUSE_NUM_IQUEUE);
}

struct rfuse_iqueue *rfuse_get_iqueue_for_async(struct fuse_conn *fc){
	int id = 0;

	id = select_round_robin(fc);

	return fc->riq[id];
}

struct rfuse_iqueue *rfuse_get_iqueue(struct fuse_conn *fc){
	int id = 0;
	int i = 0, tmp = 0;

	switch(RFUSE_SELECTION_ALGO) {
		case 0:
			id = select_round_robin(fc);
			break;
		case 1:
			id = select_thread_id();
			break;
		case 2:
			id = select_cpu_id();
			break;
		default:
			/* default is use only first rfuse_iqueue */
			id = 0;
	}

	/* Selected rfuse iqueue is congested, try to pick idle rfuse iqueue*/
	if(fc->riq[id]->num_sync_sleeping) {
		for(i = 0; i < 10; i++) {
			get_random_bytes(&tmp, sizeof(tmp) - 1);
			id = tmp % RFUSE_NUM_IQUEUE;
			if(!fc->riq[id]->num_sync_sleeping)
				break;
		}
	}
	
	return fc->riq[id];
}

struct rfuse_iqueue *rfuse_get_specific_iqueue(struct fuse_conn *fc, int id){
	return fc->riq[id];
}

struct rfuse_address_entry *rfuse_read_pending_tail(struct rfuse_iqueue *riq){
	struct ring_buffer_1 *pending = &riq->pending;
	struct rfuse_address_entry *ret = NULL;
	unsigned int head; 
	unsigned int next;

	head = smp_load_acquire(&pending->head); // Cannot touch in kernel
	next = pending->tail + 1;

	if (next - head <= pending->entries) {
		ret = &pending->kaddr[pending->tail & pending->mask];
    }
    return ret;
}

void rfuse_submit_pending_tail(struct rfuse_iqueue *riq){
	struct ring_buffer_1 *pending = &riq->pending;
	unsigned int next =  pending->tail + 1;
	smp_store_release(&pending->tail,next);
}

struct rfuse_forget_entry *rfuse_read_forgets_tail(struct rfuse_iqueue *riq){
	struct ring_buffer_3 *forgets = &riq->forgets;
	struct rfuse_forget_entry *ret = NULL;
	unsigned int head; 
	unsigned int next;

	head = smp_load_acquire(&forgets->head); // Cannot touch in kernel
	next = forgets->tail + 1;

	if (next - head <= forgets->entries) {
		ret = &forgets->kaddr[forgets->tail & forgets->mask];
    	}

    	return ret;
}

void rfuse_submit_forgets_tail(struct rfuse_iqueue *riq){
	struct ring_buffer_3 *forgets = &riq->forgets;
	unsigned int next =  forgets->tail + 1;
	smp_store_release(&forgets->tail,next);
}


struct rfuse_interrupt_entry *rfuse_read_interrupts_tail(struct rfuse_iqueue *riq){
	struct ring_buffer_2 *interrupts = &riq->interrupts;
	struct rfuse_interrupt_entry *ret = NULL;
	unsigned int head; 
	unsigned int next;

	head = smp_load_acquire(&interrupts->head); // Cannot touch in kernel
	next = interrupts->tail + 1;

	if (next - head <= interrupts->entries) {
		ret = &interrupts->kaddr[interrupts->tail & interrupts->mask];
    }
    return ret;
}

void rfuse_submit_interrupt_tail(struct rfuse_iqueue *riq){
	struct ring_buffer_2 *interrupts = &riq->interrupts;
	unsigned int next =  interrupts->tail + 1;
	smp_store_release(&interrupts->tail,next);
}


struct rfuse_address_entry *rfuse_read_complete_head(struct rfuse_iqueue *riq){
	struct ring_buffer_1 *completes = &riq->completes;
	unsigned int head = completes->head;
	unsigned int tail = smp_load_acquire(&completes->tail);
	struct rfuse_address_entry *ret = NULL;
	if(head < tail){
		ret = &completes->kaddr[head & completes->mask];
		// printk("complete head: %u\n",head & completes->mask);
	}

    return ret;
}

void rfuse_extract_complete_head(struct rfuse_iqueue *riq){
	struct ring_buffer_1 *completes = &riq->completes;
	unsigned int next = completes->head + 1;
	smp_store_release(&completes->head,next);
}

/************ 3. Request & Argument ************/

uint32_t rfuse_get_request_buffer(struct fuse_mount *fm, int riq_id){
	struct fuse_conn *fc = fm->fc;
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(fc, riq_id);
	uint32_t request_index;

	for(;;){
		spin_lock(&riq->lock);
		request_index = find_next_zero_bit(riq->reqbm.bitmap,riq->reqbm.bitmap_size,0);

		if(request_index == riq->reqbm.bitmap_size){
			// There are no empty request buffer
			riq->reqbm.full = 1; // set to full
			spin_unlock(&riq->lock);
			wait_event_interruptible(riq->waitq, !READ_ONCE(riq->reqbm.full));
		}
		else{
			__set_bit(request_index,riq->reqbm.bitmap);
			spin_unlock(&riq->lock);
			break;
		}	
	}
	return request_index;
}

void rfuse_put_request_buffer(struct fuse_mount *fm, uint32_t request_index, int riq_id){
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(fm->fc, riq_id);
	spin_lock(&riq->lock);
	__clear_bit(request_index,riq->reqbm.bitmap);

	if(riq->reqbm.full == 1){
		riq->reqbm.full = 0;
		wake_up(&riq->waitq);
	}
	spin_unlock(&riq->lock);
}

uint32_t rfuse_get_argument_buffer(struct fuse_mount *fm, int riq_id){
	struct fuse_conn *fc = fm->fc;
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(fc, riq_id);
	uint32_t arg_index;

	for(;;){
		spin_lock(&riq->lock);
		arg_index = find_next_zero_bit(riq->argbm.bitmap,riq->argbm.bitmap_size,0);

		if(arg_index == riq->argbm.bitmap_size){
			// There are no empty request buffer
			riq->argbm.full = 1; // set to full
			spin_unlock(&riq->lock);
			wait_event_interruptible(riq->waitq,!READ_ONCE(riq->argbm.full));
		}
		else{
			__set_bit(arg_index,riq->argbm.bitmap);
			spin_unlock(&riq->lock);
			break;
		}	
	}
	return arg_index;
}

void rfuse_put_argument_buffer(struct fuse_mount *fm, uint32_t arg_index, int riq_id){
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(fm->fc, riq_id);
	spin_lock(&riq->lock);

	__clear_bit(arg_index,riq->argbm.bitmap);
	
	if(riq->argbm.full == 1){
		riq->reqbm.full = 0;
		wake_up(&riq->waitq);
	}
	spin_unlock(&riq->lock);
}

static void rfuse_request_free(struct rfuse_req *req){
	if(req->in.arglen[0] != 0)
		rfuse_put_argument_buffer(req->fm, req->in.arg[0], req->riq_id);
	if(req->in.arglen[1] != 0)
		rfuse_put_argument_buffer(req->fm, req->in.arg[1], req->riq_id);
	if(req->out.arglen != 0)
		rfuse_put_argument_buffer(req->fm, req->out.arg, req->riq_id);

	rfuse_put_request_buffer(req->fm, req->index, req->riq_id);
	smp_mb();
}

void rfuse_put_request(struct rfuse_req *r_req){
	struct fuse_conn *fc;
	struct rfuse_iqueue *riq;
	
	if(!r_req){
		printk("RFUSE ERROR: trying to free a RFUSE request in the wrong place\n");
		return;
	}

	fc = r_req->fm->fc;
	riq = rfuse_get_specific_iqueue(fc, r_req->riq_id);
	if (refcount_dec_and_test(&r_req->count)) {
        if (test_bit(FR_BACKGROUND, &r_req->flags)) {
            /*
             * We get here in the unlikely case that a background
             * request was allocated but not sent
             */
            spin_lock(&riq->bg_lock);
            if (!riq->blocked)
                wake_up(&riq->blocked_waitq);
            spin_unlock(&riq->bg_lock);
        }

        if (test_bit(FR_WAITING, &r_req->flags)) {
            __clear_bit(FR_WAITING, &r_req->flags);
            rfuse_drop_waiting(fc);
        }
		rfuse_request_free(r_req);
    }  
}

struct rfuse_req *rfuse_request_alloc(struct fuse_mount *fm){
	struct fuse_conn *fc = fm->fc;
	struct rfuse_iqueue *riq = rfuse_get_iqueue(fc);
	int riq_id = riq->riq_id;
	struct rfuse_req *r_req = NULL;
	uint32_t req_index;

	req_index = rfuse_get_request_buffer(fm, riq_id); // Get a new index
	r_req = (struct rfuse_req*)&riq->kreq[req_index]; // Get a new entry

	if(r_req) {
		// Initialize request
		memset(r_req, 0, sizeof(struct rfuse_req));
		init_waitqueue_head(&r_req->waitq);
		refcount_set(&r_req->count, 1);
		__set_bit(FR_PENDING,&r_req->flags);
		r_req->fm = fm;
		r_req->index = req_index;
		r_req->riq_id = riq_id;
	}

	// INITIALIZE DONE
	return r_req;
}

struct rfuse_req *rfuse_get_req(struct fuse_mount *fm, bool for_background, bool force){
	struct fuse_conn *fc = fm->fc;
	struct rfuse_req *r_req;
	struct rfuse_iqueue *riq;
	int err;

	if(force) {
		atomic_inc(&fc->num_waiting);

		r_req = rfuse_request_alloc(fm);

		__set_bit(FR_WAITING, &r_req->flags);
		if(for_background){
			__set_bit(FR_BACKGROUND, &r_req->flags);
		} else{
			if(!r_req->nocreds)
				rfuse_force_creds(r_req);

			__set_bit(FR_FORCE, &r_req->flags);
		}
	} else {
		atomic_inc(&fc->num_waiting);

		smp_rmb();
		err = -ENOTCONN;
		if(!fc->connected) {
			goto out;
		}

		err = -ECONNREFUSED;
		if (fc->conn_error) {
			goto out; 
		}

		r_req = rfuse_request_alloc(fm);
		err = -ENOMEM;
		if (!r_req) {
			if (for_background)
				wake_up(&fc->blocked_waitq);
			goto out;
		}

		// Pass riq_id to find riq if it needs to wait
		if(rfuse_block_alloc(fc, for_background, r_req->riq_id)){
			err = -EINTR;
			riq = rfuse_get_specific_iqueue(fc, r_req->riq_id);
			if (wait_event_killable_exclusive(riq->blocked_waitq, !rfuse_block_alloc(fc, for_background, r_req->riq_id))) {
				goto out;
			}	
		}


		r_req->in.uid = from_kuid(fc->user_ns, current_fsuid());
		r_req->in.gid = from_kgid(fc->user_ns, current_fsgid());
		r_req->in.pid = pid_nr_ns(task_pid(current), fc->pid_ns);

		__set_bit(FR_WAITING, &r_req->flags);
		if (for_background) 
			__set_bit(FR_BACKGROUND, &r_req->flags);

		if (unlikely(r_req->in.uid == ((uid_t)-1) || r_req->in.gid == ((gid_t)-1))) {
			rfuse_put_request(r_req);
			return ERR_PTR(-EOVERFLOW);
		}
	}

	smp_mb();

	return r_req;  

out:
	printk("r_req allocation failed\n");
	rfuse_drop_waiting(fc);
	return ERR_PTR(err);
}

/* 
	This is special request allocation function for rfuse writeback cache 
	If failed to get request from request buffer, release file lock and wait for request buffer
*/
static uint32_t try_rfuse_get_request_buffer(struct fuse_mount *fm, int riq_id){
	struct fuse_conn *fc = fm->fc;
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(fc, riq_id);
	uint32_t request_index;

	for(;;){
		spin_lock(&riq->lock);
		request_index = find_next_zero_bit(riq->reqbm.bitmap,riq->reqbm.bitmap_size,0);

		if(request_index == riq->reqbm.bitmap_size){
			// There are no empty request buffer
			riq->reqbm.full = 1; // set to full
			spin_unlock(&riq->lock);
			return -1;
		}
		else{
			__set_bit(request_index,riq->reqbm.bitmap);
			spin_unlock(&riq->lock);
			break;
		}	
	}
	return request_index;
}

static struct rfuse_req *try_rfuse_request_alloc(struct fuse_mount *fm, spinlock_t *file_lock){
	struct fuse_conn *fc = fm->fc;
	struct rfuse_iqueue *riq = rfuse_get_iqueue_for_async(fc);
	int riq_id = riq->riq_id;
	struct rfuse_req *r_req = NULL;
	uint32_t req_index;

	do {
		req_index = try_rfuse_get_request_buffer(fm, riq_id); // Get a new index
		if(req_index == -1) {
			if(file_lock)
				spin_unlock(file_lock);
			wait_event_interruptible(riq->waitq, !READ_ONCE(riq->reqbm.full));
			if(file_lock)
				spin_lock(file_lock);
		}
	} while(req_index == -1);
	
	r_req = (struct rfuse_req*)&riq->kreq[req_index]; // Get a new entry

	if(r_req) {
		// Initialize request
		memset(r_req, 0, sizeof(struct rfuse_req));
		init_waitqueue_head(&r_req->waitq);
		refcount_set(&r_req->count, 1);
		__set_bit(FR_PENDING,&r_req->flags);
		r_req->fm = fm;
		r_req->index = req_index;
		r_req->riq_id = riq_id;
	}

	// INITIALIZE DONE
	return r_req;
}

struct rfuse_req *try_rfuse_get_req(struct fuse_mount *fm, bool for_background, bool force, spinlock_t *file_lock){
	struct fuse_conn *fc = fm->fc;
	struct rfuse_req *r_req;
	struct rfuse_iqueue *riq;
	int err;

	if(force) {
		atomic_inc(&fc->num_waiting);

		r_req = try_rfuse_request_alloc(fm, file_lock);
		err = -ENOMEM;
		if (!r_req) {
			if (for_background)
				wake_up(&fc->blocked_waitq);
			goto out;
		}

		__set_bit(FR_WAITING, &r_req->flags);
		if(for_background){
			__set_bit(FR_BACKGROUND, &r_req->flags);
		} else{
			if(!r_req->nocreds)
				rfuse_force_creds(r_req);

			__set_bit(FR_FORCE, &r_req->flags);
		}
	} else {
		atomic_inc(&fc->num_waiting);

		smp_rmb();
		err = -ENOTCONN;
		if(!fc->connected) {
			goto out;
		}

		err = -ECONNREFUSED;
		if (fc->conn_error) {
			goto out; 
		}

		r_req = try_rfuse_request_alloc(fm, file_lock);
		err = -ENOMEM;
		if (!r_req) {
			if (for_background)
				wake_up(&fc->blocked_waitq);
			goto out;
		}

		// Pass riq_id to find riq if it needs to wait
		if(rfuse_block_alloc(fc, for_background, r_req->riq_id)){
			err = -EINTR;
			riq = rfuse_get_specific_iqueue(fc, r_req->riq_id);
			if (wait_event_killable_exclusive(riq->blocked_waitq, !rfuse_block_alloc(fc, for_background, r_req->riq_id))) {
				goto out;
			}	
		}


		r_req->in.uid = from_kuid(fc->user_ns, current_fsuid());
		r_req->in.gid = from_kgid(fc->user_ns, current_fsgid());
		r_req->in.pid = pid_nr_ns(task_pid(current), fc->pid_ns);

		__set_bit(FR_WAITING, &r_req->flags);
		if (for_background) 
			__set_bit(FR_BACKGROUND, &r_req->flags);

		if (unlikely(r_req->in.uid == ((uid_t)-1) || r_req->in.gid == ((gid_t)-1))) {
			rfuse_put_request(r_req);
			return ERR_PTR(-EOVERFLOW);
		}
	}

	smp_mb();
	
	return r_req;  

out:
	printk("try r_req allocation failed\n");
	rfuse_drop_waiting(fc);
	return ERR_PTR(err);
}

/************ 4. Insert to Queue ************/

void __rfuse_get_request(struct rfuse_req *r_req){
	refcount_inc(&r_req->count);
}
void __rfuse_put_request(struct rfuse_req *r_req){
	refcount_dec(&r_req->count);
}

static int rfuse_queue_interrupt(struct rfuse_req *r_req){
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(r_req->fm->fc, r_req->riq_id);
	struct rfuse_interrupt_entry *target_entry;

	spin_lock(&riq->lock);
	/* Check for we've sent request to interrupt this req */
	if (unlikely(!test_bit(FR_INTERRUPTED, &r_req->flags))) {
		spin_unlock(&riq->lock);
		return -EINVAL;
	}
	
	// Get a new entry from the interrupt queue
	target_entry = rfuse_read_interrupts_tail(riq);
	if(!target_entry){
		printk("interrupt queue is full!\n");
		spin_unlock(&riq->lock);
		return 1;
	}
	// Inset a new Interrupt Queue Entry
	target_entry->unique = r_req->in.unique;
	rfuse_submit_interrupt_tail(riq);
	spin_unlock(&riq->lock);

	printk("RFUSE: Queue a request to the interrupt queue\n");
	return 0;
}

// FORGET QUEUE INSERT
void rfuse_queue_forget(struct fuse_conn *fc, u64 nodeid, u64 nlookup){
	struct rfuse_iqueue *riq = rfuse_get_iqueue(fc);
	struct rfuse_forget_entry *target_entry = NULL;

	spin_lock(&riq->lock);
	if (riq->connected) {
		// Allocate a new forget_entry
		target_entry = rfuse_read_forgets_tail(riq);
		if(!target_entry){
			spin_unlock(&riq->lock);
			return;
		}
		
		// Fill inside the forget entry
		target_entry->unique = rfuse_get_unique(riq); 
		target_entry->nodeid = nodeid;
		target_entry->nlookup = nlookup;

		// Commit the forget entry
		rfuse_submit_forgets_tail(riq);
	}
	spin_unlock(&riq->lock);
}


/*
	Wait completion by busy waiting, do not sleep
	We can use r_req->flags for checking whether request is finished or not
*/
static void rfuse_request_wait_answer(struct rfuse_req *r_req){
	struct fuse_conn *fc = r_req->fm->fc;
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(fc, r_req->riq_id);
	int err;

#ifdef DEBUG
	int i;
#endif

	if (!fc->no_interrupt) {
		GET_TIMESTAMPS(1)
		err = rfuse_completion_poll(fc, riq, r_req);
		GET_TIMESTAMPS(7)
	
#ifdef DEBUG
		/* print all */
		for(i = 0; i < 8; i++) {
			if (i == 0) 
				printk("rfuse experiment opcode: %llu\n", timestamps[i]);
			else if (i < 2 || i > 5)
				printk("rfuse experiment [%d]: %llu nsec\n", i, timestamps[i]);
		}
#endif

		if (!err)
			return;

		set_bit(FR_INTERRUPTED, &r_req->flags);
		smp_mb__after_atomic();
		if (test_bit(FR_SENT, &r_req->flags))
			rfuse_queue_interrupt(r_req);
	}

	if (!test_bit(FR_FORCE, &r_req->flags)) {
		/* Only fatal signals may interrupt this */
		err = wait_event_killable(r_req->waitq,
				test_bit(FR_FINISHED, &r_req->flags));
		if (!err)
			return;

		spin_lock(&riq->lock);
		/* Request is not yet in userspace, bail out */
		if (test_bit(FR_PENDING, &r_req->flags)) {
			spin_unlock(&riq->lock);
			__rfuse_put_request(r_req);
			r_req->out.error = -EINTR;
			return;
		}
		spin_unlock(&riq->lock);
	}

	/*
	 * Either request is already in userspace, or it was forced.
	 * Wait it out.
	 */
	wait_event(r_req->waitq, test_bit(FR_FINISHED, &r_req->flags));
}

static void rfuse_queue_request(struct rfuse_req *r_req){
	struct fuse_mount *fm = r_req->fm;
	struct fuse_conn *fc = fm->fc;
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(fc, r_req->riq_id);
	struct rfuse_address_entry *entry;

	// printk("RFUSE: Send %d\n",r_req->in.opcode);
	timestamps[0] = r_req->in.opcode;

	if(test_bit(FR_BACKGROUND, &r_req->flags)){
		__set_bit(FR_ASYNC,&r_req->flags);
	}

	spin_lock(&riq->lock);						// set lock
	entry = rfuse_read_pending_tail(riq);		// Get an entry
	r_req->in.unique = rfuse_get_unique(riq); 
	
	entry->request = r_req->index;				// fill entry
	if(!test_bit(FR_BACKGROUND, &r_req->flags)) // only increase the reference count for synchronous requests
		__rfuse_get_request(r_req);
	rfuse_submit_pending_tail(riq);				// Commit entry
	spin_unlock(&riq->lock);					// unlock
	
	if(waitqueue_active(&riq->idle_user_waitq)){
		wake_up(&riq->idle_user_waitq);		// Wake up idle user thread
	}
	// printk("RFUSE: Send %d END\n", r_req->in.opcode);
}

// PENDING QUEUE INSERT
ssize_t rfuse_simple_request(struct rfuse_req *r_req){
	ssize_t ret=0;

	rfuse_queue_request(r_req);
	rfuse_request_wait_answer(r_req);
	smp_rmb();

	ret = r_req->out.error;
	if (!ret && r_req->out_argvar) {
		ret = r_req->out.arglen;
	}

	return ret;
}


// MOVE (BG QUEUE --> Pending QUEUE)
static void rfuse_flush_bg_queue(struct fuse_conn *fc, int riq_id){
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(fc, riq_id);
	while (riq->active_background < riq->max_background &&
			!list_empty(&riq->bg_queue)) {
		struct rfuse_bg_entry *bg_entry;
		struct rfuse_req *r_req;

		bg_entry = list_first_entry(&riq->bg_queue, struct rfuse_bg_entry, list);
		list_del(&bg_entry->list);
		riq->active_background++;
		r_req = (struct rfuse_req*)&riq->kreq[bg_entry->request];
		kfree(bg_entry);

		rfuse_queue_request(r_req); // only queue request but not wait for it
	}
}


static bool rfuse_request_queue_background(struct rfuse_req *r_req)
{
	struct fuse_mount *fm = r_req->fm;
	struct fuse_conn *fc = fm->fc;
	struct rfuse_bg_entry *bg_entry = kmalloc_node(sizeof(struct rfuse_bg_entry), GFP_KERNEL, cpu_to_node(r_req->riq_id));
	bool queued = false;
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(fc, r_req->riq_id);

	WARN_ON(!test_bit(FR_BACKGROUND, &r_req->flags));
	if (!test_bit(FR_WAITING, &r_req->flags)) {
		__set_bit(FR_WAITING, &r_req->flags);
		atomic_inc(&fc->num_waiting);
	}
	__set_bit(FR_ISREPLY, &r_req->flags);

	// Initialize background entry
	INIT_LIST_HEAD(&bg_entry->list);
	bg_entry->request = r_req->index;
	bg_entry->riq_id = r_req->riq_id;

	spin_lock(&riq->bg_lock);
	if (likely(riq->connected)) {
		riq->num_background++;
		if (riq->num_background == riq->max_background) {
			riq->blocked = 1;
		}
		if (riq->num_background == riq->congestion_threshold && fm->sb) {
			set_bdi_congested(fm->sb->s_bdi, BLK_RW_SYNC);
			set_bdi_congested(fm->sb->s_bdi, BLK_RW_ASYNC);
		}
		list_add_tail(&bg_entry->list, &riq->bg_queue); // Add it to background queue
		rfuse_flush_bg_queue(fc, r_req->riq_id);
		queued = true;
	}
	spin_unlock(&riq->bg_lock);

	return queued;
}


// BACKGROUND QUEUE INSERT
bool rfuse_simple_background(struct fuse_mount *fm, struct rfuse_req *r_req){
	if(!rfuse_request_queue_background(r_req)){
		rfuse_put_request(r_req);
		return -ENOTCONN;
	}
	return 0;
}

void rfuse_request_end(struct rfuse_req *r_req){
	struct fuse_mount *fm = r_req->fm;
	struct fuse_conn *fc = fm->fc;
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(fc, r_req->riq_id);
	GET_TIMESTAMPS(6)
	
	if(test_bit(FR_BACKGROUND, &r_req->flags)){
		spin_lock(&riq->bg_lock);
		clear_bit(FR_BACKGROUND, &r_req->flags);
		if (riq->num_background == riq->max_background) {
			riq->blocked = 0;
			wake_up(&riq->blocked_waitq);
		} else if (!riq->blocked) {
			/*
			 * Wake up next waiter, if any.  It's okay to use
			 * waitqueue_active(), as we've already synced up
			 * fc->blocked with waiters with the wake_up() call
			 * above.
			 */
			if (waitqueue_active(&riq->blocked_waitq))
				wake_up(&riq->blocked_waitq);
		}

		if (riq->num_background == riq->congestion_threshold && fm->sb) {
			clear_bdi_congested(fm->sb->s_bdi, BLK_RW_SYNC);
			clear_bdi_congested(fm->sb->s_bdi, BLK_RW_ASYNC);
		}
		riq->num_background--;
		riq->active_background--;
		rfuse_flush_bg_queue(fc, r_req->riq_id);
		spin_unlock(&riq->bg_lock);
	}

	if (test_bit(FR_ASYNC, &r_req->flags))
		r_req->end(r_req->fm, r_req, r_req->out.error);

	rfuse_put_request(r_req);
}


// READ FROM COMPLETE QUEUE for getattr
// static void rfuse_read_complete_queue(){
// 	struct rfuse_address_entry *c_entry; 
// 	spin_lock(&riq->lock);
// 	c_entry = rfuse_read_complete_head(riq);
// 	if(c_entry){
// 		r_req = &riq->kreq[c_entry->request];
// 		outarg_rfuse = (struct fuse_attr_out*)&r_req->args;
// 		rfuse_extract_complete_head(riq);
// 	}
// 	spin_unlock(&riq->lock);
// }


/************ 5. Device Read Write ************/
/*
 * Lock the request.  Up to the next unlock_request() there mustn't be
 * anything that could cause a page-fault.  If the request was already
 * aborted bail out.
 */
static int rfuse_lock_request(struct rfuse_req *r_req)
{
	int err = 0;
	if (r_req) {
		spin_lock(&r_req->waitq.lock);
		if (test_bit(FR_ABORTED, &r_req->flags))
			err = -ENOENT;
		else
			set_bit(FR_LOCKED, &r_req->flags);
		spin_unlock(&r_req->waitq.lock);
	}
	return err;
}

/*
 * Unlock request.  If it was aborted while locked, caller is responsible
 * for unlocking and ending the request.
 */
static int rfuse_unlock_request(struct rfuse_req *r_req)
{
	int err = 0;
	if (r_req) {
		spin_lock(&r_req->waitq.lock);
		if (test_bit(FR_ABORTED, &r_req->flags))
			err = -ENOENT;
		else
			clear_bit(FR_LOCKED, &r_req->flags);
		spin_unlock(&r_req->waitq.lock);
	}
	return err;
}

struct rfuse_copy_state {
	int write;
	struct rfuse_req *r_req;
	struct iov_iter *iter;
	struct pipe_buffer *pipebufs;
	struct pipe_buffer *currbuf;
	struct pipe_inode_info *pipe;
	unsigned long nr_segs;
	struct page *pg;
	unsigned len;
	unsigned offset;
	unsigned move_pages:1;
};

static void rfuse_copy_init(struct rfuse_copy_state *rcs, int write, struct iov_iter *iter){
	memset(rcs, 0, sizeof(*rcs));
	rcs->write = write;
	rcs->iter = iter;
}


/* Unmap and put previous page of userspace buffer */
static void rfuse_copy_finish(struct rfuse_copy_state *rcs)
{
	if (rcs->currbuf) {
		struct pipe_buffer *buf = rcs->currbuf;

		if (rcs->write)
			buf->len = PAGE_SIZE - rcs->len;
		rcs->currbuf = NULL;
	} else if (rcs->pg) {
		if (rcs->write) {
			flush_dcache_page(rcs->pg);
			set_page_dirty_lock(rcs->pg);
		}
		put_page(rcs->pg);
	}
	rcs->pg = NULL;
}

/*
 * Get another pagefull of userspace buffer, and map it to kernel
 * address space, and lock request
 */
static int rfuse_copy_fill(struct rfuse_copy_state *rcs)
{
	struct page *page;
	int err;

	err = rfuse_unlock_request(rcs->r_req);
	if (err)
		return err;

	rfuse_copy_finish(rcs);
	if (rcs->pipebufs) {
		struct pipe_buffer *buf = rcs->pipebufs;

		if (!rcs->write) {
			err = pipe_buf_confirm(rcs->pipe, buf);
			if (err)
				return err;

			BUG_ON(!rcs->nr_segs);
			rcs->currbuf = buf;
			rcs->pg = buf->page;
			rcs->offset = buf->offset;
			rcs->len = buf->len;
			rcs->pipebufs++;
			rcs->nr_segs--;
		} else {
			if (rcs->nr_segs >= rcs->pipe->max_usage)
				return -EIO;

			page = alloc_page(GFP_HIGHUSER);
			if (!page)
				return -ENOMEM;

			buf->page = page;
			buf->offset = 0;
			buf->len = 0;

			rcs->currbuf = buf;
			rcs->pg = page;
			rcs->offset = 0;
			rcs->len = PAGE_SIZE;
			rcs->pipebufs++;
			rcs->nr_segs++;
		}
	} else {
		size_t off;
		err = iov_iter_get_pages(rcs->iter, &page, PAGE_SIZE, 1, &off);
		if (err < 0)
			return err;
		BUG_ON(!err);
		rcs->len = err;
		rcs->offset = off;
		rcs->pg = page;
		iov_iter_advance(rcs->iter, err);
	}

	return rfuse_lock_request(rcs->r_req);
}

/* Do as much copy to/from userspace buffer as we can */
static int rfuse_copy_do(struct rfuse_copy_state *rcs, void **val, unsigned *size)
{
	unsigned ncpy = min(*size, rcs->len);
	if (val) {
		void *pgaddr = kmap_atomic(rcs->pg);
		void *buf = pgaddr + rcs->offset;

		if (rcs->write)
			memcpy(buf, *val, ncpy);
		else
			memcpy(*val, buf, ncpy);

		kunmap_atomic(pgaddr);
		*val += ncpy;
	}
	*size -= ncpy;
	rcs->len -= ncpy;
	rcs->offset += ncpy;
	return ncpy;
}

static int rfuse_try_move_page(struct rfuse_copy_state *rcs, struct page **pagep)
{
	int err;
	struct page *oldpage = *pagep;
	struct page *newpage;
	struct pipe_buffer *buf = rcs->pipebufs;

	get_page(oldpage);
	err = rfuse_unlock_request(rcs->r_req);
	if (err)
		goto out_put_old;

	rfuse_copy_finish(rcs);

	err = pipe_buf_confirm(rcs->pipe, buf);
	if (err)
		goto out_put_old;

	BUG_ON(!rcs->nr_segs);
	rcs->currbuf = buf;
	rcs->len = buf->len;
	rcs->pipebufs++;
	rcs->nr_segs--;

	if (rcs->len != PAGE_SIZE)
		goto out_fallback;

	if (!pipe_buf_try_steal(rcs->pipe, buf))
		goto out_fallback;

	newpage = buf->page;

	if (!PageUptodate(newpage))
		SetPageUptodate(newpage);

	ClearPageMappedToDisk(newpage);

	if (rfuse_check_page(newpage) != 0)
		goto out_fallback_unlock;

	/*
	 * This is a new and locked page, it shouldn't be mapped or
	 * have any special flags on it
	 */
	if (WARN_ON(page_mapped(oldpage)))
		goto out_fallback_unlock;
	if (WARN_ON(page_has_private(oldpage)))
		goto out_fallback_unlock;
	if (WARN_ON(PageDirty(oldpage) || PageWriteback(oldpage)))
		goto out_fallback_unlock;
	if (WARN_ON(PageMlocked(oldpage)))
		goto out_fallback_unlock;

	replace_page_cache_page(oldpage, newpage);

	get_page(newpage);

	if (!(buf->flags & PIPE_BUF_FLAG_LRU))
		lru_cache_add(newpage);

	err = 0;
	spin_lock(&rcs->r_req->waitq.lock);
	if (test_bit(FR_ABORTED, &rcs->r_req->flags))
		err = -ENOENT;
	else
		*pagep = newpage;
	spin_unlock(&rcs->r_req->waitq.lock);

	if (err) {
		unlock_page(newpage);
		put_page(newpage);
		goto out_put_old;
	}

	unlock_page(oldpage);
	/* Drop ref for ap->pages[] array */
	put_page(oldpage);
	rcs->len = 0;

	err = 0;
out_put_old:
	/* Drop ref obtained in this function */
	put_page(oldpage);
	return err;

out_fallback_unlock:
	unlock_page(newpage);
out_fallback:
	rcs->pg = buf->page;
	rcs->offset = buf->offset;

	err = rfuse_lock_request(rcs->r_req);
	if (!err)
		err = 1;

	goto out_put_old;
}

static int rfuse_ref_page(struct rfuse_copy_state *rcs, struct page *page, unsigned offset, unsigned count){
	struct pipe_buffer *buf;
	int err;

	if (rcs->nr_segs >= rcs->pipe->max_usage)
		return -EIO;

	get_page(page);
	err = rfuse_unlock_request(rcs->r_req);
	if (err) {
		put_page(page);
		return err;
	}

	rfuse_copy_finish(rcs);

	buf = rcs->pipebufs;
	buf->page = page;
	buf->offset = offset;
	buf->len = count;

	rcs->pipebufs++;
	rcs->nr_segs++;
	rcs->len = 0;

	return 0;
}

static int rfuse_copy_page(struct rfuse_copy_state *rcs, struct page **pagep,
		unsigned offset, unsigned count, int zeroing){

	int err;
	struct page *page = *pagep;
	
	if(page && zeroing && count < PAGE_SIZE)
		clear_highpage(page);
	
	while(count){
		if (rcs->write && rcs->pipebufs && page) {
			return rfuse_ref_page(rcs, page, offset, count);
		} else if (!rcs->len) {
			if (rcs->move_pages && page && offset == 0 && count == PAGE_SIZE) {
				err = rfuse_try_move_page(rcs, pagep);
				if (err <= 0)
					return err;
			} else {
				err = rfuse_copy_fill(rcs);
				if (err)
					return err;
			}
		}
		if (page) {
			void *mapaddr = kmap_atomic(page);
			void *buf = mapaddr + offset;
			offset += rfuse_copy_do(rcs, &buf, &count);
			kunmap_atomic(mapaddr);
		} else
			offset += rfuse_copy_do(rcs, NULL, &count);
	}
	if(page && !rcs->write)
		flush_dcache_page(page);
	return 0;
}

static int rfuse_copy_pages(struct rfuse_copy_state *rcs, unsigned nbytes,
		int zeroing)
{
	unsigned i;
	struct rfuse_req *r_req = rcs->r_req;
	struct rfuse_pages *rp = r_req->rp;

	if(rp == NULL){
		return 0;
	}
	
	for (i = 0; i < rp->num_pages && (nbytes || zeroing); i++) {
		int err;
		unsigned int offset = rp->descs[i].offset;
		unsigned int count = min(nbytes, rp->descs[i].length);
		err = rfuse_copy_page(rcs, &rp->pages[i], offset, count, zeroing);
		if (err)
			return err;

		nbytes -= count;
	}
	return 0;
}

ssize_t rfuse_dev_do_read(struct fuse_dev *fud, struct file *file, struct iov_iter *to, size_t garbage, loff_t index)
{
	struct fuse_conn *fc = fud->fc;
	struct rfuse_pages *rp;
	unsigned i;
	unsigned nbytes;
	ssize_t res = 0;

	struct rfuse_copy_state rcs;	
	int riq_id = (int)((index & RFUSE_RIQ_ID_MASK) >> 16);
	int req_index = (int)((index & RFUSE_REQ_IDX_MASK) >> 32);
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(fc, riq_id);
	struct rfuse_req *r_req = (struct rfuse_req*)&riq->kreq[req_index];


	rp = r_req->rp;
	rfuse_copy_init(&rcs, 1, to);	

	rcs.r_req = r_req;
	nbytes = r_req->in.arglen[0];

	for(i =0; i<rp->num_pages && (nbytes); i++){
		int err;
		unsigned int offset = rp->descs[i].offset;
		unsigned int count = min(nbytes,rp->descs[i].length);

		err = rfuse_copy_page(&rcs, &rp->pages[i], offset, count, 0);
		if(err)
			return err;
		nbytes -= count;
		res += count;
	}
	rfuse_copy_finish(&rcs);

	return res;
}

static int rfuse_dev_prep_splice_read(struct fuse_dev *fud, struct rfuse_req *r_req, struct rfuse_copy_state *rcs)
{
	int err = 0;
	struct fuse_write_in *inarg = (struct fuse_write_in *)&r_req->args;
	err = rfuse_copy_pages(rcs, inarg->size, 0);
	rfuse_copy_finish(rcs);

	return err;
}

ssize_t rfuse_dev_splice_read(struct file *in, loff_t *ppos, struct pipe_inode_info *pipe, size_t len, unsigned int flags)
{
	int total, ret;
	int page_nr = 0;
	struct pipe_buffer *bufs;
	struct rfuse_copy_state rcs;	
	struct fuse_dev *fud = fuse_get_dev(in);
	struct fuse_conn *fc = fud->fc;

	int riq_id = (int)((*ppos & RFUSE_RIQ_ID_MASK) >> 16);
	int req_index = (int)((*ppos & RFUSE_REQ_IDX_MASK) >> 32);
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(fc, riq_id);
	struct rfuse_req *r_req = (struct rfuse_req*)&riq->kreq[req_index];

	if (!fud)
		return -EPERM;

	bufs = kvmalloc_array(pipe->max_usage, sizeof(struct pipe_buffer),
			GFP_KERNEL);
	if (!bufs)
		return -ENOMEM;

	rfuse_copy_init(&rcs, 1, NULL);
	rcs.pipebufs = bufs;
	rcs.pipe = pipe;
	rcs.r_req = r_req;
	ret = rfuse_dev_prep_splice_read(fud, r_req, &rcs);
	if (ret < 0)
		goto out;

	if (pipe_occupancy(pipe->head, pipe->tail) + rcs.nr_segs > pipe->max_usage) {
		ret = -EIO;
		goto out;
	}

	for (ret = total = 0; page_nr < rcs.nr_segs; total += ret) {
		/*
		 * Need to be careful about this.  Having buf->ops in module
		 * code can Oops if the buffer persists after module unload.
		 */
		bufs[page_nr].ops = &nosteal_pipe_buf_ops;
		bufs[page_nr].flags = 0;
		ret = add_to_pipe(pipe, &bufs[page_nr++]);
		if (unlikely(ret < 0))
			break;
	}
	if (total)
		ret = total;
out:
	for (; page_nr < rcs.nr_segs; page_nr++)
		put_page(bufs[page_nr].page);

	kvfree(bufs);
	return ret;
}

ssize_t rfuse_dev_do_write(struct fuse_dev *fud, struct iov_iter *from, unsigned nbytes, size_t index){
	struct fuse_conn *fc = fud->fc;
	struct rfuse_pages *rp;
	unsigned i;
	ssize_t res = 0;

	struct rfuse_copy_state rcs;	
	int riq_id = (int)((index & RFUSE_RIQ_ID_MASK) >> 16);
	int req_index = (int)((index & RFUSE_REQ_IDX_MASK) >> 32);
	struct rfuse_iqueue *riq = rfuse_get_specific_iqueue(fc, riq_id);
	struct rfuse_req *r_req = (struct rfuse_req*)&riq->kreq[req_index];

	rp = r_req->rp;
	rfuse_copy_init(&rcs, 0 ,from);	

	rcs.r_req = r_req;
	
	if(r_req->out.arglen > nbytes)
		r_req->out.arglen = nbytes;

	for(i =0; i < rp->num_pages && (nbytes); i++){
		int err;
		unsigned int offset = rp->descs[i].offset;
		unsigned int count = min(nbytes,rp->descs[i].length);
	
		err = rfuse_copy_page(&rcs, &rp->pages[i],offset, count,0);
		if(err)
			return err;
		nbytes -= count;
		res += count;
	}
	rfuse_copy_finish(&rcs);

	return res;
}

static int rfuse_dev_do_splice_write(struct fuse_dev *fud, struct rfuse_req *r_req, struct rfuse_copy_state *rcs, size_t len)
{
	int err = 0;
	
	if (!r_req->page_replace)
		rcs->move_pages = 0;

	err = rfuse_copy_pages(rcs, len, r_req->page_zeroing);
	rfuse_copy_finish(rcs);

	if(test_bit(FR_BACKGROUND, &r_req->flags)) {
		rfuse_request_end(r_req);
	} else {
		set_bit(FR_FINISHED, &r_req->flags);
		if(waitqueue_active(&r_req->waitq)) {
			wake_up(&r_req->waitq);
		}
	}

	return err ? err : len;
}

ssize_t rfuse_dev_splice_write(struct pipe_inode_info *pipe, struct file *out, loff_t *ppos, size_t len, unsigned int flags)
{
	unsigned int head, tail, mask, count;
	unsigned nbuf;
	unsigned idx;
	struct pipe_buffer *bufs;
	struct rfuse_copy_state rcs;
	struct fuse_dev *fud;
	struct fuse_conn *fc;
	size_t rem;
	ssize_t ret;
	int riq_id;
	int req_index;
	struct rfuse_iqueue *riq;
	struct rfuse_req *r_req;

	fud = fuse_get_dev(out);
	if (!fud)
		return -EPERM;
	fc = fud->fc;
	riq_id = (int)((*ppos & RFUSE_RIQ_ID_MASK) >> 16);
	req_index = (int)((*ppos & RFUSE_REQ_IDX_MASK) >> 32);
	riq = rfuse_get_specific_iqueue(fc, riq_id);
	r_req = (struct rfuse_req*)&riq->kreq[req_index];

	pipe_lock(pipe);

	head = pipe->head;
	tail = pipe->tail;
	mask = pipe->ring_size - 1;
	count = head - tail;

	bufs = kvmalloc_array(count, sizeof(struct pipe_buffer), GFP_KERNEL);
	if (!bufs) {
		pipe_unlock(pipe);
		return -ENOMEM;
	}

	nbuf = 0;
	rem = 0;
	for (idx = tail; idx != head && rem < len; idx++)
		rem += pipe->bufs[idx & mask].len;

	ret = -EINVAL;
	if (rem < len)
		goto out_free;

	rem = len;
	while (rem) {
		struct pipe_buffer *ibuf;
		struct pipe_buffer *obuf;

		if (WARN_ON(nbuf >= count || tail == head))
			goto out_free;

		ibuf = &pipe->bufs[tail & mask];
		obuf = &bufs[nbuf];

		if (rem >= ibuf->len) {
			*obuf = *ibuf;
			ibuf->ops = NULL;
			tail++;
			pipe->tail = tail;
		} else {
			if (!pipe_buf_get(pipe, ibuf))
				goto out_free;

			*obuf = *ibuf;
			obuf->flags &= ~PIPE_BUF_FLAG_GIFT;
			obuf->len = rem;
			ibuf->offset += obuf->len;
			ibuf->len -= obuf->len;
		}
		nbuf++;
		rem -= obuf->len;
	}
	pipe_unlock(pipe);

	rfuse_copy_init(&rcs, 0, NULL);
	rcs.pipebufs = bufs;
	rcs.nr_segs = nbuf;
	rcs.pipe = pipe;
	rcs.r_req = r_req;

	if (flags & SPLICE_F_MOVE)
		rcs.move_pages = 1;

	ret = rfuse_dev_do_splice_write(fud, r_req, &rcs, len);
	pipe_lock(pipe);
out_free:
	for (idx = 0; idx < nbuf; idx++)
		pipe_buf_release(pipe, &bufs[idx]);
	pipe_unlock(pipe);
	kvfree(bufs);
	return ret;
}

/************ 6. Unmount ************/
void rfuse_abort_conn(struct fuse_conn *fc){
	struct rfuse_iqueue **riq = fc->riq;
	unsigned int i;

	for(i = 0; i < RFUSE_NUM_IQUEUE; i++) {
		spin_lock(&riq[i]->lock);
		riq[i]->connected = 0;

		spin_lock(&riq[i]->bg_lock);
		rfuse_flush_bg_queue(fc, riq[i]->riq_id);
		spin_unlock(&riq[i]->bg_lock);

		wake_up_all(&riq[i]->waitq);
		wake_up_all(&riq[i]->idle_user_waitq);
		spin_unlock(&riq[i]->lock);
	}
}
EXPORT_SYMBOL_GPL(rfuse_abort_conn);
