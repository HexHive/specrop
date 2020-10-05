#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>

#define VERIFY(x, errmsg)				\
	if(!((x))){							\
		fprintf(stderr, "%s:%d>>\n\t", 	\
				__func__, __LINE__); 	\
		perror(errmsg);					\
		exit(1);						\
	}


void pin(unsigned core) { 
	cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(core, &cpuset);

  VERIFY(sched_setaffinity(0, sizeof(cpuset), &cpuset) == 0,
    	   "Unable to pin thread");
}

volatile unsigned junk = 0;
void busy_wait() {
	for (unsigned i = 0; i < 0xff; i++)
		junk ^= i;
}