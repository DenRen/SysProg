#pragma once

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#define dump(obj)    printf(#obj ": %u\n",   (obj))
#define dump_lu(obj) printf(#obj ": %lu\n",  (obj))
#define dump_b(obj)  printf(#obj ": %d\n", !!(obj))
#define dump_x(obj)  printf(#obj ": %x\n",   (obj))

void print_location(int fd, const char* file, long line, const char* func);

#define PRINT_ERR(expression)													\
	do {																		\
		print_location(STDERR_FILENO, __FILE__, __LINE__, __PRETTY_FUNCTION__); \
		dprintf(STDERR_FILENO, "\n");											\
		perror(#expression);													\
	} while(0)

#define CHECK_NNEG(func)	\
	do {					\
		int res = ((func)); \
		if (res < 0)		\
		{					\
			PRINT_ERR(func);\
			return -errno;	\
		}					\
	} while(0)

#define CHECK_TRUE(cond)	\
	do {					\
		if (!(cond))		\
		{					\
			PRINT_ERR(cond);\
			return -errno;	\
		}					\
	} while(0)
