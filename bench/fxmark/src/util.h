/* SPDX-License-Identifier: MIT */
#ifndef __UTIL_H__
#define __UTIL_H__

int mkdir_p(const char *path);

inline static unsigned int pseudo_random(unsigned int x_n)
{
	/* 
	 * NOTE: linear congruential generator 
	 *   http://en.wikipedia.org/wiki/Linear_congruential_generator 
	 */
	return 1103515245 * x_n + 12345;
}

#endif /* __UTIL_H__ */
