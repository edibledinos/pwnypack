from pwnypack.shellcode.linux import Linux
from pwnypack.shellcode.arm import ARM
from pwnypack.shellcode.arm.thumb import ARMThumb
from pwnypack.shellcode.arm.thumb_mixed import ARMThumbMixed
from pwnypack.shellcode.mutable_data import gnu_as_mutable_data_finalizer
from pwnypack.shellcode.stack_data import stack_data_finalizer


__all__ = ['LinuxARMMutable', 'LinuxARMThumbMutable', 'LinuxARMThumbMixedMutable',
           'LinuxARMStack', 'LinuxARMThumbStack', 'LinuxARMThumbMixedStack']


class LinuxARM(Linux, ARM):
    """
    An environment that targets a generic Linux ARM machine.
    """

    SYSCALL_ARG_MAP = [ARM.R0, ARM.R1, ARM.R2, ARM.R3, ARM.R4, ARM.R5]

    SYSCALL_REG = ARM.R7
    SYSCALL_RET_REG = ARM.R0
    SYSCALL_INSTR = 'swi #0'

    SYSCALL_MAP = {
        Linux.sys_restart_syscall: 0,
        Linux.sys_exit: 1,
        Linux.sys_fork: 2,
        Linux.sys_read: 3,
        Linux.sys_write: 4,
        Linux.sys_open: 5,
        Linux.sys_close: 6,
        Linux.sys_creat: 8,
        Linux.sys_link: 9,
        Linux.sys_unlink: 10,
        Linux.sys_execve: 11,
        Linux.sys_chdir: 12,
        Linux.sys_time: 13,
        Linux.sys_mknod: 14,
        Linux.sys_chmod: 15,
        Linux.sys_lchown: 16,
        Linux.sys_lseek: 19,
        Linux.sys_getpid: 20,
        Linux.sys_mount: 21,
        Linux.sys_umount2: 22,
        Linux.sys_setuid: 23,
        Linux.sys_getuid: 24,
        Linux.sys_stime: 25,
        Linux.sys_ptrace: 26,
        Linux.sys_alarm: 27,
        Linux.sys_pause: 29,
        Linux.sys_utime: 30,
        Linux.sys_access: 33,
        Linux.sys_nice: 34,
        Linux.sys_sync: 36,
        Linux.sys_kill: 37,
        Linux.sys_rename: 38,
        Linux.sys_mkdir: 39,
        Linux.sys_rmdir: 40,
        Linux.sys_dup: 41,
        Linux.sys_pipe: 42,
        Linux.sys_times: 43,
        Linux.sys_brk: 45,
        Linux.sys_setgid: 46,
        Linux.sys_getgid: 47,
        Linux.sys_geteuid: 49,
        Linux.sys_getegid: 50,
        Linux.sys_acct: 51,
        Linux.sys_ioctl: 54,
        Linux.sys_fcntl: 55,
        Linux.sys_setpgid: 57,
        Linux.sys_umask: 60,
        Linux.sys_chroot: 61,
        Linux.sys_ustat: 62,
        Linux.sys_dup2: 63,
        Linux.sys_getppid: 64,
        Linux.sys_getpgrp: 65,
        Linux.sys_setsid: 66,
        Linux.sys_sigaction: 67,
        Linux.sys_setreuid: 70,
        Linux.sys_setregid: 71,
        Linux.sys_sigsuspend: 72,
        Linux.sys_sigpending: 73,
        Linux.sys_sethostname: 74,
        Linux.sys_setrlimit: 75,
        Linux.sys_getrlimit: 76,
        Linux.sys_getrusage: 77,
        Linux.sys_gettimeofday: 78,
        Linux.sys_settimeofday: 79,
        Linux.sys_getgroups: 80,
        Linux.sys_setgroups: 81,
        Linux.sys_select: 82,
        Linux.sys_symlink: 83,
        Linux.sys_readlink: 85,
        Linux.sys_uselib: 86,
        Linux.sys_swapon: 87,
        Linux.sys_reboot: 88,
        Linux.sys_old_readdir: 89,
        Linux.sys_old_mmap: 90,
        Linux.sys_munmap: 91,
        Linux.sys_truncate: 92,
        Linux.sys_ftruncate: 93,
        Linux.sys_fchmod: 94,
        Linux.sys_fchown: 95,
        Linux.sys_getpriority: 96,
        Linux.sys_setpriority: 97,
        Linux.sys_statfs: 99,
        Linux.sys_fstatfs: 100,
        Linux.sys_socketcall: 102,
        Linux.sys_syslog: 103,
        Linux.sys_setitimer: 104,
        Linux.sys_getitimer: 105,
        Linux.sys_stat: 106,
        Linux.sys_lstat: 107,
        Linux.sys_fstat: 108,
        Linux.sys_vhangup: 111,
        Linux.sys_wait4: 114,
        Linux.sys_swapoff: 115,
        Linux.sys_sysinfo: 116,
        Linux.sys_ipc: 117,
        Linux.sys_fsync: 118,
        Linux.sys_clone: 120,
        Linux.sys_setdomainname: 121,
        Linux.sys_uname: 122,
        Linux.sys_adjtimex: 124,
        Linux.sys_mprotect: 125,
        Linux.sys_sigprocmask: 126,
        Linux.sys_init_module: 128,
        Linux.sys_delete_module: 129,
        Linux.sys_quotactl: 131,
        Linux.sys_getpgid: 132,
        Linux.sys_fchdir: 133,
        Linux.sys_bdflush: 134,
        Linux.sys_sysfs: 135,
        Linux.sys_personality: 136,
        Linux.sys_setfsuid: 138,
        Linux.sys_setfsgid: 139,
        Linux.sys_getdents: 141,
        Linux.sys_flock: 143,
        Linux.sys_msync: 144,
        Linux.sys_readv: 145,
        Linux.sys_writev: 146,
        Linux.sys_getsid: 147,
        Linux.sys_fdatasync: 148,
        Linux.sys_mlock: 150,
        Linux.sys_munlock: 151,
        Linux.sys_mlockall: 152,
        Linux.sys_munlockall: 153,
        Linux.sys_sched_setparam: 154,
        Linux.sys_sched_getparam: 155,
        Linux.sys_sched_setscheduler: 156,
        Linux.sys_sched_getscheduler: 157,
        Linux.sys_sched_yield: 158,
        Linux.sys_sched_get_priority_max: 159,
        Linux.sys_sched_get_priority_min: 160,
        Linux.sys_sched_rr_get_interval: 161,
        Linux.sys_nanosleep: 162,
        Linux.sys_mremap: 163,
        Linux.sys_setresuid: 164,
        Linux.sys_getresuid: 165,
        Linux.sys_poll: 168,
        Linux.sys_setresgid: 170,
        Linux.sys_getresgid: 171,
        Linux.sys_prctl: 172,
        Linux.sys_rt_sigaction: 174,
        Linux.sys_rt_sigprocmask: 175,
        Linux.sys_rt_sigpending: 176,
        Linux.sys_rt_sigtimedwait: 177,
        Linux.sys_rt_sigqueueinfo: 178,
        Linux.sys_rt_sigsuspend: 179,
        Linux.sys_pread64: 180,
        Linux.sys_pwrite64: 181,
        Linux.sys_chown: 182,
        Linux.sys_getcwd: 183,
        Linux.sys_capget: 184,
        Linux.sys_capset: 185,
        Linux.sys_sigaltstack: 186,
        Linux.sys_sendfile: 187,
        Linux.sys_vfork: 190,
        Linux.sys_mmap2: 192,
        Linux.sys_truncate64: 193,
        Linux.sys_ftruncate64: 194,
        Linux.sys_stat64: 195,
        Linux.sys_lstat64: 196,
        Linux.sys_fstat64: 197,
        Linux.sys_getdents64: 217,
        Linux.sys_pivot_root: 218,
        Linux.sys_mincore: 219,
        Linux.sys_madvise: 220,
        Linux.sys_fcntl64: 221,
        Linux.sys_gettid: 224,
        Linux.sys_readahead: 225,
        Linux.sys_setxattr: 226,
        Linux.sys_lsetxattr: 227,
        Linux.sys_fsetxattr: 228,
        Linux.sys_getxattr: 229,
        Linux.sys_lgetxattr: 230,
        Linux.sys_fgetxattr: 231,
        Linux.sys_listxattr: 232,
        Linux.sys_llistxattr: 233,
        Linux.sys_flistxattr: 234,
        Linux.sys_removexattr: 235,
        Linux.sys_lremovexattr: 236,
        Linux.sys_fremovexattr: 237,
        Linux.sys_tkill: 238,
        Linux.sys_sendfile64: 239,
        Linux.sys_futex: 240,
        Linux.sys_sched_setaffinity: 241,
        Linux.sys_sched_getaffinity: 242,
        Linux.sys_io_setup: 243,
        Linux.sys_io_destroy: 244,
        Linux.sys_io_getevents: 245,
        Linux.sys_io_submit: 246,
        Linux.sys_io_cancel: 247,
        Linux.sys_exit_group: 248,
        Linux.sys_lookup_dcookie: 249,
        Linux.sys_epoll_create: 250,
        Linux.sys_epoll_ctl: 251,
        Linux.sys_epoll_wait: 252,
        Linux.sys_remap_file_pages: 253,
        Linux.sys_set_tid_address: 256,
        Linux.sys_timer_create: 257,
        Linux.sys_timer_settime: 258,
        Linux.sys_timer_gettime: 259,
        Linux.sys_timer_getoverrun: 260,
        Linux.sys_timer_delete: 261,
        Linux.sys_clock_settime: 262,
        Linux.sys_clock_gettime: 263,
        Linux.sys_clock_getres: 264,
        Linux.sys_clock_nanosleep: 265,
        Linux.sys_statfs64: 266,
        Linux.sys_fstatfs64: 267,
        Linux.sys_tgkill: 268,
        Linux.sys_utimes: 269,
        Linux.sys_pciconfig_iobase: 271,
        Linux.sys_pciconfig_read: 272,
        Linux.sys_pciconfig_write: 273,
        Linux.sys_mq_open: 274,
        Linux.sys_mq_unlink: 275,
        Linux.sys_mq_timedsend: 276,
        Linux.sys_mq_timedreceive: 277,
        Linux.sys_mq_notify: 278,
        Linux.sys_mq_getsetattr: 279,
        Linux.sys_waitid: 280,
        Linux.sys_socket: 281,
        Linux.sys_bind: 282,
        Linux.sys_connect: 283,
        Linux.sys_listen: 284,
        Linux.sys_accept: 285,
        Linux.sys_getsockname: 286,
        Linux.sys_getpeername: 287,
        Linux.sys_socketpair: 288,
        Linux.sys_send: 289,
        Linux.sys_sendto: 290,
        Linux.sys_recv: 291,
        Linux.sys_recvfrom: 292,
        Linux.sys_shutdown: 293,
        Linux.sys_setsockopt: 294,
        Linux.sys_getsockopt: 295,
        Linux.sys_sendmsg: 296,
        Linux.sys_recvmsg: 297,
        Linux.sys_semop: 298,
        Linux.sys_semget: 299,
        Linux.sys_semctl: 300,
        Linux.sys_msgsnd: 301,
        Linux.sys_msgrcv: 302,
        Linux.sys_msgget: 303,
        Linux.sys_msgctl: 304,
        Linux.sys_shmat: 305,
        Linux.sys_shmdt: 306,
        Linux.sys_shmget: 307,
        Linux.sys_shmctl: 308,
        Linux.sys_add_key: 309,
        Linux.sys_request_key: 310,
        Linux.sys_keyctl: 311,
        Linux.sys_semtimedop: 312,
        Linux.sys_ioprio_set: 314,
        Linux.sys_ioprio_get: 315,
        Linux.sys_inotify_init: 316,
        Linux.sys_inotify_add_watch: 317,
        Linux.sys_inotify_rm_watch: 318,
        Linux.sys_mbind: 319,
        Linux.sys_get_mempolicy: 320,
        Linux.sys_set_mempolicy: 321,
        Linux.sys_openat: 322,
        Linux.sys_mkdirat: 323,
        Linux.sys_mknodat: 324,
        Linux.sys_fchownat: 325,
        Linux.sys_futimesat: 326,
        Linux.sys_fstatat64: 327,
        Linux.sys_unlinkat: 328,
        Linux.sys_renameat: 329,
        Linux.sys_linkat: 330,
        Linux.sys_symlinkat: 331,
        Linux.sys_readlinkat: 332,
        Linux.sys_fchmodat: 333,
        Linux.sys_faccessat: 334,
        Linux.sys_pselect6: 335,
        Linux.sys_ppoll: 336,
        Linux.sys_unshare: 337,
        Linux.sys_set_robust_list: 338,
        Linux.sys_get_robust_list: 339,
        Linux.sys_splice: 340,
        Linux.sys_tee: 342,
        Linux.sys_vmsplice: 343,
        Linux.sys_move_pages: 344,
        Linux.sys_getcpu: 345,
        Linux.sys_epoll_pwait: 346,
        Linux.sys_kexec_load: 347,
        Linux.sys_utimensat: 348,
        Linux.sys_signalfd: 349,
        Linux.sys_timerfd_create: 350,
        Linux.sys_eventfd: 351,
        Linux.sys_fallocate: 352,
        Linux.sys_timerfd_settime: 353,
        Linux.sys_timerfd_gettime: 354,
        Linux.sys_signalfd4: 355,
        Linux.sys_eventfd2: 356,
        Linux.sys_epoll_create1: 357,
        Linux.sys_dup3: 358,
        Linux.sys_pipe2: 359,
        Linux.sys_inotify_init1: 360,
        Linux.sys_preadv: 361,
        Linux.sys_pwritev: 362,
        Linux.sys_rt_tgsigqueueinfo: 363,
        Linux.sys_perf_event_open: 364,
        Linux.sys_recvmmsg: 365,
        Linux.sys_accept4: 366,
        Linux.sys_fanotify_init: 367,
        Linux.sys_fanotify_mark: 368,
        Linux.sys_prlimit64: 369,
        Linux.sys_name_to_handle_at: 370,
        Linux.sys_open_by_handle_at: 371,
        Linux.sys_clock_adjtime: 372,
        Linux.sys_syncfs: 373,
        Linux.sys_sendmmsg: 374,
        Linux.sys_setns: 375,
        Linux.sys_process_vm_readv: 376,
        Linux.sys_process_vm_writev: 377,
        Linux.sys_kcmp: 378,
        Linux.sys_finit_module: 379,
        Linux.sys_sched_setattr: 380,
        Linux.sys_sched_getattr: 381,
        Linux.sys_renameat2: 382,
        Linux.sys_seccomp: 383,
        Linux.sys_getrandom: 384,
        Linux.sys_memfd_create: 385,
        Linux.sys_bpf: 386,
        Linux.sys_execveat: 387,
    }


class LinuxARMThumb(ARMThumb, LinuxARM):
    """
    An environment that targets a generic Linux ARM machine in Thumb mode.
    """


class LinuxARMThumbMixed(ARMThumbMixed, LinuxARM):
    """
    An environment that targets a generic Linux ARM machine that starts out
    in ARM mode but switches to Thumb mode.
    """


_mutable_data_finalizer = gnu_as_mutable_data_finalizer(lambda env, _: ['\tadr %s, __data' % env.OFFSET_REG], '@')


class LinuxARMMutable(LinuxARM):
    """
    An environment that targets a 32-bit Linux ARM machine in a writable segment.
    """

    data_finalizer = _mutable_data_finalizer


class LinuxARMThumbMutable(LinuxARMThumb):
    """
    An environment that targets a 32-bit Linux ARM machine using the Thumb
    instruction set in a writable segment.
    """

    data_finalizer = _mutable_data_finalizer


class LinuxARMThumbMixedMutable(LinuxARMThumbMixed):
    """
    An environment that targets a 32-bit Linux ARM machine, switches to Thumb
    mode and resides in a writable segment.
    """

    data_finalizer = _mutable_data_finalizer


_stack_data_finalizer = stack_data_finalizer(8)


class LinuxARMStack(LinuxARM):
    """
    An environment that targets a 32-bit Linux ARM machine that allocates
    the required data on the stack.
    """

    data_finalizer = _stack_data_finalizer


class LinuxARMThumbStack(LinuxARMThumb):
    """
    An environment that targets a 32-bit Linux ARM machine using the Thumb
    instruction set that allocates the required data on the stack.
    """

    data_finalizer = _stack_data_finalizer


class LinuxARMThumbMixedStack(LinuxARMThumbMixed):
    """
    An environment that targets a 32-bit Linux ARM machine, switches to Thumb
    mode and allocates the required data on the stack.
    """

    data_finalizer = _stack_data_finalizer
