#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/kernel/list.h"

void syscall_init (void);
void close_all_fds(void);

#endif /* userprog/syscall.h */
