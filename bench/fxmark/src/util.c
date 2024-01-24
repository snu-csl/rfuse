// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <linux/limits.h>

int mkdir_p(const char *path)
{
	char cmd[PATH_MAX*2];
	snprintf(cmd, PATH_MAX*2, "mkdir -p %s", path);
	return system(cmd);
}
