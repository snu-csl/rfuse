#include "config.h"
#include "fuse_lowlevel.h"
#include "fuse_i.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>


/**
 * Loop used for the Rfuse User level daemon
 * Polls on the Submission Queue Tail...
 */

int fuse_session_loop(struct fuse_session *se)
{
	int res = 0;
	int forget = 0;
	int riq_id = 0;

	while (!fuse_session_exited(se)) {
        //printf("Read from Queue!\n");
        // rfuse_read_queue(se,NULL,forget, riq_id);
        /**
		  Currently We check the forget queue once and 
		  pending queue once, We do not check the interrupt queue yet..
		**/
	forget = (forget + 1) % 2;
	riq_id = (riq_id + 1) % RFUSE_NUM_IQUEUE;
		/**
		Current version sleeps for 1 usec 
		  **/
        //usleep(1);
    }

	if(res > 0)
		/* No error, just the length of the most recently read
		   request */
		res = 0;
	if(se->error != 0)
		res = se->error;
	fuse_session_reset(se);
	return res;
}
