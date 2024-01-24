#include "fuse_i.h"
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/jiffies.h>

void rfuse_sleep_comp(struct fuse_conn *fc, struct rfuse_iqueue *riq, struct rfuse_req *r_req) {
	spin_lock(&r_req->waitq.lock);
	set_bit(FR_NEEDWAKEUP, &r_req->flags);
	spin_unlock(&r_req->waitq.lock);

	spin_lock(&riq->lock);
	riq->num_sync_sleeping++;
	spin_unlock(&riq->lock);

	wait_event_interruptible(r_req->waitq, !fc->connected || test_bit(FR_FINISHED, &r_req->flags));

	spin_lock(&riq->lock);
	riq->num_sync_sleeping--;
	spin_unlock(&riq->lock);
}

int rfuse_completion_poll(struct fuse_conn *fc, struct rfuse_iqueue *riq, struct rfuse_req *r_req)
{   
	unsigned long max_idle_due = jiffies + usecs_to_jiffies(RFUSE_COMP_MAX_IDLE);
	
	while(fc->connected) {
		if(test_bit(FR_FINISHED, &r_req->flags)){
			rfuse_request_end(r_req);
			return 0;
		}

		 if(time_after(jiffies, max_idle_due)){
	 		rfuse_sleep_comp(fc, riq, r_req);
		 }

		schedule();
	}

	return -ENOTCONN;
}
