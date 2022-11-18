#include "print_lib.h"

void print_location(int fd, const char* file, long line, const char* func)
{
	dprintf(fd, "%s:%li in %s function", file, line, func);
}