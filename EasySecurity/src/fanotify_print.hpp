#pragma once

#include <sys/fanotify.h>

void print_mask(uint64_t mask);
int print_cmdline(const char* path);
int print_md(const struct fanotify_event_metadata* md);
