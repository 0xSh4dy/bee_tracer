#ifndef CONTROLLER_H
#define CONTROLLER_H

#define MAX_SYSCALL_NR 335
#define MAX_ARGS 6

#include <sys/syscall.h>

typedef enum
{
    SYS_ENTER,
    SYS_EXIT
} event_mode;

struct inner_syscall_info
{
    union
    {
        struct
        {
            char name[32];
            int num_args;
            long syscall_nr;
            void *args[MAX_ARGS];
        };
        long retval;
    };
    event_mode mode;
};

struct default_syscall_info{
    char name[32];
    int num_args;
};

const struct default_syscall_info syscalls[MAX_SYSCALL_NR] = {
    [SYS_fork] = {"fork", 0},
    [SYS_alarm] = {"alarm", 1},
    [SYS_brk] = {"brk", 1},
    [SYS_close] = {"close", 1},
    [SYS_exit] = {"exit", 1},
    [SYS_exit_group] = {"exit_group", 1},
    [SYS_set_tid_address] = {"set_tid_address", 1},
    [SYS_set_robust_list] = {"set_robust_list", 1},
    [SYS_access] = {"access", 2},
    [SYS_arch_prctl] = {"arch_prctl", 2},
    [SYS_kill] = {"kill", 2},
    [SYS_listen] = {"listen", 2},
    [SYS_munmap] = {"sys_munmap", 2},
    [SYS_open] = {"open", 2},
    [SYS_stat] = {"stat", 2},
    [SYS_fstat] = {"fstat", 2},
    [SYS_lstat] = {"lstat", 2},
    [SYS_accept] = {"accept", 3},
    [SYS_connect] = {"connect", 3},
    [SYS_execve] = {"execve", 3},
    [SYS_ioctl] = {"ioctl", 3},
    [SYS_getrandom] = {"getrandom", 3},
    [SYS_lseek] = {"lseek", 3},
    [SYS_poll] = {"poll", 3},
    [SYS_read] = {"read", 3},
    [SYS_write] = {"write", 3},
    [SYS_mprotect] = {"mprotect", 3},
    [SYS_openat] = {"openat", 3},
    [SYS_socket] = {"socket", 3},
    [SYS_newfstatat] = {"newfstatat", 4},
    [SYS_pread64] = {"pread64", 4},
    [SYS_prlimit64] = {"prlimit64", 4},
    [SYS_rseq] = {"rseq", 4},
    [SYS_sendfile] = {"sendfile", 4},
    [SYS_socketpair] = {"socketpair", 4},
    [SYS_mmap] = {"mmap", 6},
    [SYS_recvfrom] = {"recvfrom", 6},
    [SYS_sendto] = {"sendto", 6},
};

#endif
