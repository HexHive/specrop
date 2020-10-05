#pragma once
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
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

#define SREPN(n, str) 	SREP##n(str)
#define SREP2(str)			str str
#define SREP4(str)			SREP2(SREP2(str))
#define SREP8(str)			SREP2(SREP4(str))
#define SREP16(str)			SREP4(SREP4(str))
#define SREP32(str)			SREP8(SREP4(str))
#define SREP128(str)		SREP32(SREP4(str))
#define SREP1024(str)		SREP32(SREP32(str))
