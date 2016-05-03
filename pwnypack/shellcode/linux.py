from pwnypack.shellcode.base import BaseEnvironment
from pwnypack.shellcode.ops import SyscallInvoke
from pwnypack.shellcode.types import NUMERIC, CHARP, CHARPP, PTR, SyscallDef


__all__ = ['Linux']


class Linux(BaseEnvironment):
    """
    This mix-in defines all the common Linux syscalls and the syscall
    mechanism.
    """

    sys_time = SyscallDef('sys_time', PTR)  #:
    sys_stime = SyscallDef('sys_stime', PTR)  #:
    sys_gettimeofday = SyscallDef('sys_gettimeofday', PTR, PTR)  #:
    sys_settimeofday = SyscallDef('sys_settimeofday', PTR, PTR)  #:
    sys_adjtimex = SyscallDef('sys_adjtimex', PTR)  #:
    sys_times = SyscallDef('sys_times', PTR)  #:
    sys_gettid = SyscallDef('sys_gettid')  #:
    sys_nanosleep = SyscallDef('sys_nanosleep', PTR, PTR)  #:
    sys_alarm = SyscallDef('sys_alarm', NUMERIC)  #:
    sys_getpid = SyscallDef('sys_getpid')  #:
    sys_getppid = SyscallDef('sys_getppid')  #:
    sys_getuid = SyscallDef('sys_getuid')  #:
    sys_geteuid = SyscallDef('sys_geteuid')  #:
    sys_getgid = SyscallDef('sys_getgid')  #:
    sys_getegid = SyscallDef('sys_getegid')  #:
    sys_getresuid = SyscallDef('sys_getresuid', PTR, PTR, PTR)  #:
    sys_getresgid = SyscallDef('sys_getresgid', PTR, PTR, PTR)  #:
    sys_getpgid = SyscallDef('sys_getpgid', NUMERIC)  #:
    sys_getpgrp = SyscallDef('sys_getpgrp')  #:
    sys_getsid = SyscallDef('sys_getsid', NUMERIC)  #:
    sys_getgroups = SyscallDef('sys_getgroups', NUMERIC, PTR)  #:
    sys_setregid = SyscallDef('sys_setregid', NUMERIC, NUMERIC)  #:
    sys_setgid = SyscallDef('sys_setgid', NUMERIC)  #:
    sys_setreuid = SyscallDef('sys_setreuid', NUMERIC, NUMERIC)  #:
    sys_setuid = SyscallDef('sys_setuid', NUMERIC)  #:
    sys_setresuid = SyscallDef('sys_setresuid', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_setresgid = SyscallDef('sys_setresgid', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_setfsuid = SyscallDef('sys_setfsuid', NUMERIC)  #:
    sys_setfsgid = SyscallDef('sys_setfsgid', NUMERIC)  #:
    sys_setpgid = SyscallDef('sys_setpgid', NUMERIC, NUMERIC)  #:
    sys_setsid = SyscallDef('sys_setsid')  #:
    sys_setgroups = SyscallDef('sys_setgroups', NUMERIC, PTR)  #:
    sys_acct = SyscallDef('sys_acct', CHARP)  #:
    sys_capget = SyscallDef('sys_capget', PTR, PTR)  #:
    sys_capset = SyscallDef('sys_capset', PTR, PTR)  #:
    sys_personality = SyscallDef('sys_personality', NUMERIC)  #:
    sys_sigpending = SyscallDef('sys_sigpending', PTR)  #:
    sys_sigprocmask = SyscallDef('sys_sigprocmask', NUMERIC, PTR, PTR)  #:
    sys_sigaltstack = SyscallDef('sys_sigaltstack', PTR, PTR)  #:
    sys_getitimer = SyscallDef('sys_getitimer', NUMERIC, PTR)  #:
    sys_setitimer = SyscallDef('sys_setitimer', NUMERIC, PTR, PTR)  #:
    sys_timer_create = SyscallDef('sys_timer_create', NUMERIC, PTR, PTR)  #:
    sys_timer_gettime = SyscallDef('sys_timer_gettime', NUMERIC, PTR)  #:
    sys_timer_getoverrun = SyscallDef('sys_timer_getoverrun', NUMERIC)  #:
    sys_timer_settime = SyscallDef('sys_timer_settime', NUMERIC, NUMERIC, PTR, PTR)  #:
    sys_timer_delete = SyscallDef('sys_timer_delete', NUMERIC)  #:
    sys_clock_settime = SyscallDef('sys_clock_settime', NUMERIC, PTR)  #:
    sys_clock_gettime = SyscallDef('sys_clock_gettime', NUMERIC, PTR)  #:
    sys_clock_adjtime = SyscallDef('sys_clock_adjtime', NUMERIC, PTR)  #:
    sys_clock_getres = SyscallDef('sys_clock_getres', NUMERIC, PTR)  #:
    sys_clock_nanosleep = SyscallDef('sys_clock_nanosleep', NUMERIC, NUMERIC, PTR, PTR)  #:
    sys_nice = SyscallDef('sys_nice', NUMERIC)  #:
    sys_sched_setscheduler = SyscallDef('sys_sched_setscheduler', NUMERIC, NUMERIC, PTR)  #:
    sys_sched_setparam = SyscallDef('sys_sched_setparam', NUMERIC, PTR)  #:
    sys_sched_setattr = SyscallDef('sys_sched_setattr', NUMERIC, PTR, NUMERIC)  #:
    sys_sched_getscheduler = SyscallDef('sys_sched_getscheduler', NUMERIC)  #:
    sys_sched_getparam = SyscallDef('sys_sched_getparam', NUMERIC, PTR)  #:
    sys_sched_getattr = SyscallDef('sys_sched_getattr', NUMERIC, PTR, NUMERIC, NUMERIC)  #:
    sys_sched_setaffinity = SyscallDef('sys_sched_setaffinity', NUMERIC, NUMERIC, PTR)  #:
    sys_sched_getaffinity = SyscallDef('sys_sched_getaffinity', NUMERIC, NUMERIC, PTR)  #:
    sys_sched_yield = SyscallDef('sys_sched_yield')  #:
    sys_sched_get_priority_max = SyscallDef('sys_sched_get_priority_max', NUMERIC)  #:
    sys_sched_get_priority_min = SyscallDef('sys_sched_get_priority_min', NUMERIC)  #:
    sys_sched_rr_get_interval = SyscallDef('sys_sched_rr_get_interval', NUMERIC, PTR)  #:
    sys_setpriority = SyscallDef('sys_setpriority', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_getpriority = SyscallDef('sys_getpriority', NUMERIC, NUMERIC)  #:
    sys_shutdown = SyscallDef('sys_shutdown', NUMERIC, NUMERIC)  #:
    sys_reboot = SyscallDef('sys_reboot', NUMERIC, NUMERIC, NUMERIC, PTR)  #:
    sys_restart_syscall = SyscallDef('sys_restart_syscall')  #:
    sys_kexec_load = SyscallDef('sys_kexec_load', NUMERIC, NUMERIC, PTR, NUMERIC)  #:
    sys_kexec_file_load = SyscallDef('sys_kexec_file_load', NUMERIC, NUMERIC, NUMERIC, CHARP, NUMERIC)  #:
    sys_exit = SyscallDef('sys_exit', NUMERIC)  #:
    sys_exit_group = SyscallDef('sys_exit_group', NUMERIC)  #:
    sys_wait4 = SyscallDef('sys_wait4', NUMERIC, PTR, NUMERIC, PTR)  #:
    sys_waitid = SyscallDef('sys_waitid', NUMERIC, NUMERIC, PTR, NUMERIC, PTR)  #:
    sys_waitpid = SyscallDef('sys_waitpid', NUMERIC, PTR, NUMERIC)  #:
    sys_set_tid_address = SyscallDef('sys_set_tid_address', PTR)  #:
    sys_futex = SyscallDef('sys_futex', PTR, NUMERIC, NUMERIC, PTR, PTR, NUMERIC)  #:
    sys_init_module = SyscallDef('sys_init_module', PTR, NUMERIC, CHARP)  #:
    sys_delete_module = SyscallDef('sys_delete_module', CHARP, NUMERIC)  #:
    sys_sigsuspend = SyscallDef('sys_sigsuspend', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_rt_sigsuspend = SyscallDef('sys_rt_sigsuspend', PTR, NUMERIC)  #:
    sys_sigaction = SyscallDef('sys_sigaction', NUMERIC, PTR, PTR)  #:
    sys_rt_sigaction = SyscallDef('sys_rt_sigaction', NUMERIC, PTR, PTR, NUMERIC)  #:
    sys_rt_sigprocmask = SyscallDef('sys_rt_sigprocmask', NUMERIC, PTR, PTR, NUMERIC)  #:
    sys_rt_sigpending = SyscallDef('sys_rt_sigpending', PTR, NUMERIC)  #:
    sys_rt_sigtimedwait = SyscallDef('sys_rt_sigtimedwait', PTR, PTR, PTR, NUMERIC)  #:
    sys_rt_tgsigqueueinfo = SyscallDef('sys_rt_tgsigqueueinfo', NUMERIC, NUMERIC, NUMERIC, PTR)  #:
    sys_kill = SyscallDef('sys_kill', NUMERIC, NUMERIC)  #:
    sys_tgkill = SyscallDef('sys_tgkill', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_tkill = SyscallDef('sys_tkill', NUMERIC, NUMERIC)  #:
    sys_rt_sigqueueinfo = SyscallDef('sys_rt_sigqueueinfo', NUMERIC, NUMERIC, PTR)  #:
    sys_sgetmask = SyscallDef('sys_sgetmask')  #:
    sys_ssetmask = SyscallDef('sys_ssetmask', NUMERIC)  #:
    sys_signal = SyscallDef('sys_signal', NUMERIC, PTR)  #:
    sys_pause = SyscallDef('sys_pause')  #:
    sys_sync = SyscallDef('sys_sync')  #:
    sys_fsync = SyscallDef('sys_fsync', NUMERIC)  #:
    sys_fdatasync = SyscallDef('sys_fdatasync', NUMERIC)  #:
    sys_bdflush = SyscallDef('sys_bdflush', NUMERIC, NUMERIC)  #:
    sys_mount = SyscallDef('sys_mount', CHARP, CHARP, CHARP, NUMERIC, PTR)  #:
    sys_umount2 = SyscallDef('sys_umount', CHARP, NUMERIC)  #:
    sys_umount = SyscallDef('sys_oldumount', CHARP)  #:
    sys_truncate = SyscallDef('sys_truncate', CHARP, NUMERIC)  #:
    sys_ftruncate = SyscallDef('sys_ftruncate', NUMERIC, NUMERIC)  #:
    sys_stat = SyscallDef('sys_stat', CHARP, PTR)  #:
    sys_statfs = SyscallDef('sys_statfs', CHARP, PTR)  #:
    sys_statfs64 = SyscallDef('sys_statfs64', CHARP, NUMERIC, PTR)  #:
    sys_fstatfs = SyscallDef('sys_fstatfs', NUMERIC, PTR)  #:
    sys_fstatfs64 = SyscallDef('sys_fstatfs64', NUMERIC, NUMERIC, PTR)  #:
    sys_lstat = SyscallDef('sys_lstat', CHARP, PTR)  #:
    sys_fstat = SyscallDef('sys_fstat', NUMERIC, PTR)  #:
    sys_newstat = SyscallDef('sys_newstat', CHARP, PTR)  #:
    sys_newlstat = SyscallDef('sys_newlstat', CHARP, PTR)  #:
    sys_newfstat = SyscallDef('sys_newfstat', NUMERIC, PTR)  #:
    sys_ustat = SyscallDef('sys_ustat', NUMERIC, PTR)  #:
    sys_stat64 = SyscallDef('sys_stat64', CHARP, PTR)  #:
    sys_fstat64 = SyscallDef('sys_fstat64', NUMERIC, PTR)  #:
    sys_lstat64 = SyscallDef('sys_lstat64', CHARP, PTR)  #:
    sys_fstatat64 = SyscallDef('sys_fstatat64', NUMERIC, CHARP, PTR, NUMERIC)  #:
    sys_truncate64 = SyscallDef('sys_truncate64', CHARP, NUMERIC)  #:
    sys_ftruncate64 = SyscallDef('sys_ftruncate64', NUMERIC, NUMERIC)  #:
    sys_setxattr = SyscallDef('sys_setxattr', CHARP, CHARP, PTR, NUMERIC, NUMERIC)  #:
    sys_lsetxattr = SyscallDef('sys_lsetxattr', CHARP, CHARP, PTR, NUMERIC, NUMERIC)  #:
    sys_fsetxattr = SyscallDef('sys_fsetxattr', NUMERIC, CHARP, PTR, NUMERIC, NUMERIC)  #:
    sys_getxattr = SyscallDef('sys_getxattr', CHARP, CHARP, PTR, NUMERIC)  #:
    sys_lgetxattr = SyscallDef('sys_lgetxattr', CHARP, CHARP, PTR, NUMERIC)  #:
    sys_fgetxattr = SyscallDef('sys_fgetxattr', NUMERIC, CHARP, PTR, NUMERIC)  #:
    sys_listxattr = SyscallDef('sys_listxattr', CHARP, CHARP, NUMERIC)  #:
    sys_llistxattr = SyscallDef('sys_llistxattr', CHARP, CHARP, NUMERIC)  #:
    sys_flistxattr = SyscallDef('sys_flistxattr', NUMERIC, CHARP, NUMERIC)  #:
    sys_removexattr = SyscallDef('sys_removexattr', CHARP, CHARP)  #:
    sys_lremovexattr = SyscallDef('sys_lremovexattr', CHARP, CHARP)  #:
    sys_fremovexattr = SyscallDef('sys_fremovexattr', NUMERIC, CHARP)  #:
    sys_brk = SyscallDef('sys_brk', NUMERIC)  #:
    sys_mprotect = SyscallDef('sys_mprotect', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_mremap = SyscallDef('sys_mremap', NUMERIC, NUMERIC, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_remap_file_pages = SyscallDef('sys_remap_file_pages', NUMERIC, NUMERIC, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_msync = SyscallDef('sys_msync', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_fadvise64 = SyscallDef('sys_fadvise64', NUMERIC, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_fadvise64_64 = SyscallDef('sys_fadvise64_64', NUMERIC, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_munmap = SyscallDef('sys_munmap', NUMERIC, NUMERIC)  #:
    sys_mlock = SyscallDef('sys_mlock', NUMERIC, NUMERIC)  #:
    sys_munlock = SyscallDef('sys_munlock', NUMERIC, NUMERIC)  #:
    sys_mlockall = SyscallDef('sys_mlockall', NUMERIC)  #:
    sys_munlockall = SyscallDef('sys_munlockall')  #:
    sys_madvise = SyscallDef('sys_madvise', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_mincore = SyscallDef('sys_mincore', NUMERIC, NUMERIC, PTR)  #:
    sys_pivot_root = SyscallDef('sys_pivot_root', CHARP, CHARP)  #:
    sys_chroot = SyscallDef('sys_chroot', CHARP)  #:
    sys_mknod = SyscallDef('sys_mknod', CHARP, NUMERIC, NUMERIC)  #:
    sys_link = SyscallDef('sys_link', CHARP, CHARP)  #:
    sys_symlink = SyscallDef('sys_symlink', CHARP, CHARP)  #:
    sys_unlink = SyscallDef('sys_unlink', CHARP)  #:
    sys_rename = SyscallDef('sys_rename', CHARP, CHARP)  #:
    sys_chmod = SyscallDef('sys_chmod', CHARP, NUMERIC)  #:
    sys_fchmod = SyscallDef('sys_fchmod', NUMERIC, NUMERIC)  #:
    sys_fcntl = SyscallDef('sys_fcntl', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_fcntl64 = SyscallDef('sys_fcntl64', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_pipe = SyscallDef('sys_pipe', PTR)  #:
    sys_pipe2 = SyscallDef('sys_pipe2', PTR, NUMERIC)  #:
    sys_dup = SyscallDef('sys_dup', NUMERIC)  #:
    sys_dup2 = SyscallDef('sys_dup2', NUMERIC, NUMERIC)  #:
    sys_dup3 = SyscallDef('sys_dup3', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_ioperm = SyscallDef('sys_ioperm', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_ioctl = SyscallDef('sys_ioctl', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_flock = SyscallDef('sys_flock', NUMERIC, NUMERIC)  #:
    sys_io_setup = SyscallDef('sys_io_setup', NUMERIC, PTR)  #:
    sys_io_destroy = SyscallDef('sys_io_destroy', PTR)  #:
    sys_io_getevents = SyscallDef('sys_io_getevents', PTR, NUMERIC, NUMERIC, PTR, PTR)  #:
    sys_io_submit = SyscallDef('sys_io_submit', PTR, NUMERIC, PTR)  #:
    sys_io_cancel = SyscallDef('sys_io_cancel', PTR, PTR, PTR)  #:
    sys_sendfile = SyscallDef('sys_sendfile', NUMERIC, NUMERIC, PTR, NUMERIC)  #:
    sys_sendfile64 = SyscallDef('sys_sendfile64', NUMERIC, NUMERIC, PTR, NUMERIC)  #:
    sys_readlink = SyscallDef('sys_readlink', CHARP, CHARP, NUMERIC)  #:
    sys_creat = SyscallDef('sys_creat', CHARP, NUMERIC)  #:
    sys_open = SyscallDef('sys_open', CHARP, NUMERIC, NUMERIC)  #:
    sys_close = SyscallDef('sys_close', NUMERIC)  #:
    sys_access = SyscallDef('sys_access', CHARP, NUMERIC)  #:
    sys_vhangup = SyscallDef('sys_vhangup')  #:
    sys_chown = SyscallDef('sys_chown', CHARP, NUMERIC, NUMERIC)  #:
    sys_lchown = SyscallDef('sys_lchown', CHARP, NUMERIC, NUMERIC)  #:
    sys_fchown = SyscallDef('sys_fchown', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_chown16 = SyscallDef('sys_chown16', CHARP, NUMERIC, NUMERIC)  #:
    sys_lchown16 = SyscallDef('sys_lchown16', CHARP, NUMERIC, NUMERIC)  #:
    sys_fchown16 = SyscallDef('sys_fchown16', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_setregid16 = SyscallDef('sys_setregid16', NUMERIC, NUMERIC)  #:
    sys_setgid16 = SyscallDef('sys_setgid16', NUMERIC)  #:
    sys_setreuid16 = SyscallDef('sys_setreuid16', NUMERIC, NUMERIC)  #:
    sys_setuid16 = SyscallDef('sys_setuid16', NUMERIC)  #:
    sys_setresuid16 = SyscallDef('sys_setresuid16', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_getresuid16 = SyscallDef('sys_getresuid16', PTR, PTR, PTR)  #:
    sys_setresgid16 = SyscallDef('sys_setresgid16', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_getresgid16 = SyscallDef('sys_getresgid16', PTR, PTR, PTR)  #:
    sys_setfsuid16 = SyscallDef('sys_setfsuid16', NUMERIC)  #:
    sys_setfsgid16 = SyscallDef('sys_setfsgid16', NUMERIC)  #:
    sys_getgroups16 = SyscallDef('sys_getgroups16', NUMERIC, PTR)  #:
    sys_setgroups16 = SyscallDef('sys_setgroups16', NUMERIC, PTR)  #:
    sys_getuid16 = SyscallDef('sys_getuid16')  #:
    sys_geteuid16 = SyscallDef('sys_geteuid16')  #:
    sys_getgid16 = SyscallDef('sys_getgid16')  #:
    sys_getegid16 = SyscallDef('sys_getegid16')  #:
    sys_utime = SyscallDef('sys_utime', CHARP, PTR)  #:
    sys_utimes = SyscallDef('sys_utimes', CHARP, PTR)  #:
    sys_lseek = SyscallDef('sys_lseek', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_llseek = SyscallDef('sys_llseek', NUMERIC, NUMERIC, NUMERIC, PTR, NUMERIC)  #:
    sys_read = SyscallDef('sys_read', NUMERIC, CHARP, NUMERIC)  #:
    sys_readahead = SyscallDef('sys_readahead', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_readv = SyscallDef('sys_readv', NUMERIC, PTR, NUMERIC)  #:
    sys_write = SyscallDef('sys_write', NUMERIC, CHARP, NUMERIC)  #:
    sys_writev = SyscallDef('sys_writev', NUMERIC, PTR, NUMERIC)  #:
    sys_pread64 = SyscallDef('sys_pread64', NUMERIC, CHARP, NUMERIC, NUMERIC)  #:
    sys_pwrite64 = SyscallDef('sys_pwrite64', NUMERIC, CHARP, NUMERIC, NUMERIC)  #:
    sys_preadv = SyscallDef('sys_preadv', NUMERIC, PTR, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_preadv2 = SyscallDef('sys_preadv2', NUMERIC, PTR, NUMERIC, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_pwritev = SyscallDef('sys_pwritev', NUMERIC, PTR, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_pwritev2 = SyscallDef('sys_pwritev2', NUMERIC, PTR, NUMERIC, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_getcwd = SyscallDef('sys_getcwd', CHARP, NUMERIC)  #:
    sys_mkdir = SyscallDef('sys_mkdir', CHARP, NUMERIC)  #:
    sys_chdir = SyscallDef('sys_chdir', CHARP)  #:
    sys_fchdir = SyscallDef('sys_fchdir', NUMERIC)  #:
    sys_rmdir = SyscallDef('sys_rmdir', CHARP)  #:
    sys_lookup_dcookie = SyscallDef('sys_lookup_dcookie', NUMERIC, CHARP, NUMERIC)  #:
    sys_quotactl = SyscallDef('sys_quotactl', NUMERIC, CHARP, NUMERIC, PTR)  #:
    sys_getdents = SyscallDef('sys_getdents', NUMERIC, PTR, NUMERIC)  #:
    sys_getdents64 = SyscallDef('sys_getdents64', NUMERIC, PTR, NUMERIC)  #:
    sys_setsockopt = SyscallDef('sys_setsockopt', NUMERIC, NUMERIC, NUMERIC, CHARP, NUMERIC)  #:
    sys_getsockopt = SyscallDef('sys_getsockopt', NUMERIC, NUMERIC, NUMERIC, CHARP, PTR)  #:
    sys_bind = SyscallDef('sys_bind', NUMERIC, PTR, NUMERIC)  #:
    sys_connect = SyscallDef('sys_connect', NUMERIC, PTR, NUMERIC)  #:
    sys_accept = SyscallDef('sys_accept', NUMERIC, PTR, PTR)  #:
    sys_accept4 = SyscallDef('sys_accept4', NUMERIC, PTR, PTR, NUMERIC)  #:
    sys_getsockname = SyscallDef('sys_getsockname', NUMERIC, PTR, PTR)  #:
    sys_getpeername = SyscallDef('sys_getpeername', NUMERIC, PTR, PTR)  #:
    sys_send = SyscallDef('sys_send', NUMERIC, PTR, NUMERIC, NUMERIC)  #:
    sys_sendto = SyscallDef('sys_sendto', NUMERIC, PTR, NUMERIC, NUMERIC, PTR, NUMERIC)  #:
    sys_sendmsg = SyscallDef('sys_sendmsg', NUMERIC, PTR, NUMERIC)  #:
    sys_sendmmsg = SyscallDef('sys_sendmmsg', NUMERIC, PTR, NUMERIC, NUMERIC)  #:
    sys_recv = SyscallDef('sys_recv', NUMERIC, PTR, NUMERIC, NUMERIC)  #:
    sys_recvfrom = SyscallDef('sys_recvfrom', NUMERIC, PTR, NUMERIC, NUMERIC, PTR, PTR)  #:
    sys_recvmsg = SyscallDef('sys_recvmsg', NUMERIC, PTR, NUMERIC)  #:
    sys_recvmmsg = SyscallDef('sys_recvmmsg', NUMERIC, PTR, NUMERIC, NUMERIC, PTR)  #:
    sys_socket = SyscallDef('sys_socket', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_socketpair = SyscallDef('sys_socketpair', NUMERIC, NUMERIC, NUMERIC, PTR)  #:
    sys_socketcall = SyscallDef('sys_socketcall', NUMERIC, PTR)  #:
    sys_listen = SyscallDef('sys_listen', NUMERIC, NUMERIC)  #:
    sys_poll = SyscallDef('sys_poll', PTR, NUMERIC, NUMERIC)  #:
    sys_select = SyscallDef('sys_select', NUMERIC, PTR, PTR, PTR, PTR)  #:
    sys_old_select = SyscallDef('sys_old_select', PTR)  #:
    sys_epoll_create = SyscallDef('sys_epoll_create', NUMERIC)  #:
    sys_epoll_create1 = SyscallDef('sys_epoll_create1', NUMERIC)  #:
    sys_epoll_ctl = SyscallDef('sys_epoll_ctl', NUMERIC, NUMERIC, NUMERIC, PTR)  #:
    sys_epoll_wait = SyscallDef('sys_epoll_wait', NUMERIC, PTR, NUMERIC, NUMERIC)  #:
    sys_epoll_pwait = SyscallDef('sys_epoll_pwait', NUMERIC, PTR, NUMERIC, NUMERIC, PTR, NUMERIC)  #:
    sys_gethostname = SyscallDef('sys_gethostname', CHARP, NUMERIC)  #:
    sys_sethostname = SyscallDef('sys_sethostname', CHARP, NUMERIC)  #:
    sys_setdomainname = SyscallDef('sys_setdomainname', CHARP, NUMERIC)  #:
    sys_newuname = SyscallDef('sys_newuname', PTR)  #:
    sys_uname = SyscallDef('sys_uname', PTR)  #:
    sys_olduname = SyscallDef('sys_olduname', PTR)  #:
    sys_getrlimit = SyscallDef('sys_getrlimit', NUMERIC, PTR)  #:
    sys_old_getrlimit = SyscallDef('sys_old_getrlimit', NUMERIC, PTR)  #:
    sys_setrlimit = SyscallDef('sys_setrlimit', NUMERIC, PTR)  #:
    sys_prlimit64 = SyscallDef('sys_prlimit64', NUMERIC, NUMERIC, PTR, PTR)  #:
    sys_getrusage = SyscallDef('sys_getrusage', NUMERIC, PTR)  #:
    sys_umask = SyscallDef('sys_umask', NUMERIC)  #:
    sys_msgget = SyscallDef('sys_msgget', NUMERIC, NUMERIC)  #:
    sys_msgsnd = SyscallDef('sys_msgsnd', NUMERIC, PTR, NUMERIC, NUMERIC)  #:
    sys_msgrcv = SyscallDef('sys_msgrcv', NUMERIC, PTR, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_msgctl = SyscallDef('sys_msgctl', NUMERIC, NUMERIC, PTR)  #:
    sys_semget = SyscallDef('sys_semget', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_semop = SyscallDef('sys_semop', NUMERIC, PTR, NUMERIC)  #:
    sys_semctl = SyscallDef('sys_semctl', NUMERIC, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_semtimedop = SyscallDef('sys_semtimedop', NUMERIC, PTR, NUMERIC, PTR)  #:
    sys_shmat = SyscallDef('sys_shmat', NUMERIC, CHARP, NUMERIC)  #:
    sys_shmget = SyscallDef('sys_shmget', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_shmdt = SyscallDef('sys_shmdt', CHARP)  #:
    sys_shmctl = SyscallDef('sys_shmctl', NUMERIC, NUMERIC, PTR)  #:
    sys_ipc = SyscallDef('sys_ipc', NUMERIC, NUMERIC, NUMERIC, NUMERIC, PTR, NUMERIC)  #:
    sys_mq_open = SyscallDef('sys_mq_open', CHARP, NUMERIC, NUMERIC, PTR)  #:
    sys_mq_unlink = SyscallDef('sys_mq_unlink', CHARP)  #:
    sys_mq_timedsend = SyscallDef('sys_mq_timedsend', NUMERIC, CHARP, NUMERIC, NUMERIC, PTR)  #:
    sys_mq_timedreceive = SyscallDef('sys_mq_timedreceive', NUMERIC, CHARP, NUMERIC, PTR, PTR)  #:
    sys_mq_notify = SyscallDef('sys_mq_notify', NUMERIC, PTR)  #:
    sys_mq_getsetattr = SyscallDef('sys_mq_getsetattr', NUMERIC, PTR, PTR)  #:
    sys_pciconfig_iobase = SyscallDef('sys_pciconfig_iobase', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_pciconfig_read = SyscallDef('sys_pciconfig_read', NUMERIC, NUMERIC, NUMERIC, NUMERIC, PTR)  #:
    sys_pciconfig_write = SyscallDef('sys_pciconfig_write', NUMERIC, NUMERIC, NUMERIC, NUMERIC, PTR)  #:
    sys_prctl = SyscallDef('sys_prctl', NUMERIC, NUMERIC, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_swapon = SyscallDef('sys_swapon', CHARP, NUMERIC)  #:
    sys_swapoff = SyscallDef('sys_swapoff', CHARP)  #:
    sys_sysctl = SyscallDef('sys_sysctl', PTR)  #:
    sys_sysinfo = SyscallDef('sys_sysinfo', PTR)  #:
    sys_sysfs = SyscallDef('sys_sysfs', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_nfsservctl = SyscallDef(NUMERIC, PTR, PTR)  #:
    sys_syslog = SyscallDef('sys_syslog', NUMERIC, CHARP, NUMERIC)  #:
    sys_uselib = SyscallDef('sys_uselib', CHARP)  #:
    sys_ni_syscall = SyscallDef('sys_ni_syscall')  #:
    sys_ptrace = SyscallDef('sys_ptrace', NUMERIC, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_add_key = SyscallDef('sys_add_key', CHARP, CHARP, PTR, NUMERIC, NUMERIC)  #:
    sys_request_key = SyscallDef('sys_request_key', CHARP, CHARP, CHARP, NUMERIC)  #:
    sys_keyctl = SyscallDef('sys_keyctl', NUMERIC, NUMERIC, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_ioprio_set = SyscallDef('sys_ioprio_set', NUMERIC, NUMERIC, NUMERIC)  #:
    sys_ioprio_get = SyscallDef('sys_ioprio_get', NUMERIC, NUMERIC)  #:
    sys_set_mempolicy = SyscallDef('sys_set_mempolicy', NUMERIC, PTR, NUMERIC)  #:
    sys_migrate_pages = SyscallDef('sys_migrate_pages', NUMERIC, NUMERIC, PTR, PTR)  #:
    sys_move_pages = SyscallDef('sys_move_pages', NUMERIC, NUMERIC, PTR, PTR, PTR, NUMERIC)  #:
    sys_mbind = SyscallDef('sys_mbind', NUMERIC, NUMERIC, NUMERIC, PTR, NUMERIC, NUMERIC)  #:
    sys_get_mempolicy = SyscallDef('sys_get_mempolicy', PTR, PTR, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_inotify_init = SyscallDef('sys_inotify_init')  #:
    sys_inotify_init1 = SyscallDef('sys_inotify_init1', NUMERIC)  #:
    sys_inotify_add_watch = SyscallDef('sys_inotify_add_watch', NUMERIC, CHARP, NUMERIC)  #:
    sys_inotify_rm_watch = SyscallDef('sys_inotify_rm_watch', NUMERIC, NUMERIC)  #:
    sys_spu_run = SyscallDef('sys_spu_run', NUMERIC, PTR, PTR)  #:
    sys_spu_create = SyscallDef('sys_spu_create', CHARP, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_mknodat = SyscallDef('sys_mknodat', NUMERIC, CHARP, NUMERIC, NUMERIC)  #:
    sys_mkdirat = SyscallDef('sys_mkdirat', NUMERIC, CHARP, NUMERIC)  #:
    sys_unlinkat = SyscallDef('sys_unlinkat', NUMERIC, CHARP, NUMERIC)  #:
    sys_symlinkat = SyscallDef('sys_symlinkat', CHARP, NUMERIC, CHARP)  #:
    sys_linkat = SyscallDef('sys_linkat', NUMERIC, CHARP, NUMERIC, CHARP, NUMERIC)  #:
    sys_renameat = SyscallDef('sys_renameat', NUMERIC, CHARP, NUMERIC, CHARP)  #:
    sys_renameat2 = SyscallDef('sys_renameat2', NUMERIC, CHARP, NUMERIC, CHARP, NUMERIC)  #:
    sys_futimesat = SyscallDef('sys_futimesat', NUMERIC, CHARP, PTR)  #:
    sys_faccessat = SyscallDef('sys_faccessat', NUMERIC, CHARP, NUMERIC)  #:
    sys_fchmodat = SyscallDef('sys_fchmodat', NUMERIC, CHARP, NUMERIC)  #:
    sys_fchownat = SyscallDef('sys_fchownat', NUMERIC, CHARP, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_openat = SyscallDef('sys_openat', NUMERIC, CHARP, NUMERIC, NUMERIC)  #:
    sys_newfstatat = SyscallDef('sys_newfstatat', NUMERIC, CHARP, PTR, NUMERIC)  #:
    sys_readlinkat = SyscallDef('sys_readlinkat', NUMERIC, CHARP, CHARP, NUMERIC)  #:
    sys_utimensat = SyscallDef('sys_utimensat', NUMERIC, CHARP, PTR, NUMERIC)  #:
    sys_unshare = SyscallDef('sys_unshare', NUMERIC)  #:
    sys_splice = SyscallDef('sys_splice', NUMERIC, PTR, NUMERIC, PTR, NUMERIC, NUMERIC)  #:
    sys_vmsplice = SyscallDef('sys_vmsplice', NUMERIC, PTR, NUMERIC, NUMERIC)  #:
    sys_tee = SyscallDef('sys_tee', NUMERIC, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_sync_file_range = SyscallDef('sys_sync_file_range', NUMERIC, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_sync_file_range2 = SyscallDef('sys_sync_file_range2', NUMERIC, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_get_robust_list = SyscallDef('sys_get_robust_list', NUMERIC, PTR, PTR)  #:
    sys_set_robust_list = SyscallDef('sys_set_robust_list', PTR, NUMERIC)  #:
    sys_getcpu = SyscallDef('sys_getcpu', PTR, PTR, PTR)  #:
    sys_signalfd = SyscallDef('sys_signalfd', NUMERIC, PTR, NUMERIC)  #:
    sys_signalfd4 = SyscallDef('sys_signalfd4', NUMERIC, PTR, NUMERIC, NUMERIC)  #:
    sys_timerfd_create = SyscallDef('sys_timerfd_create', NUMERIC, NUMERIC)  #:
    sys_timerfd_settime = SyscallDef('sys_timerfd_settime', NUMERIC, NUMERIC, PTR, PTR)  #:
    sys_timerfd_gettime = SyscallDef('sys_timerfd_gettime', NUMERIC, PTR)  #:
    sys_eventfd = SyscallDef('sys_eventfd', NUMERIC)  #:
    sys_eventfd2 = SyscallDef('sys_eventfd2', NUMERIC, NUMERIC)  #:
    sys_memfd_create = SyscallDef('sys_memfd_create', CHARP, NUMERIC)  #:
    sys_userfaultfd = SyscallDef('sys_userfaultfd', NUMERIC)  #:
    sys_fallocate = SyscallDef('sys_fallocate', NUMERIC, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_old_readdir = SyscallDef('sys_old_readdir', NUMERIC, PTR, NUMERIC)  #:
    sys_pselect6 = SyscallDef('sys_pselect6', NUMERIC, PTR, PTR, PTR, PTR, PTR)  #:
    sys_ppoll = SyscallDef('sys_ppoll', PTR, NUMERIC, PTR, PTR, NUMERIC)  #:
    sys_fanotify_init = SyscallDef('sys_fanotify_init', NUMERIC, NUMERIC)  #:
    sys_fanotify_mark = SyscallDef('sys_fanotify_mark', NUMERIC, NUMERIC, NUMERIC, NUMERIC, PTR)  #:
    sys_syncfs = SyscallDef('sys_syncfs', NUMERIC)  #:
    sys_fork = SyscallDef('sys_fork')  #:
    sys_vfork = SyscallDef('sys_vfork')  #:
    sys_clone = SyscallDef('sys_clone', NUMERIC, NUMERIC, PTR, PTR, NUMERIC)  #:
    sys_execve = SyscallDef('sys_execve', CHARP, CHARPP, CHARPP)  #:
    sys_perf_event_open = SyscallDef('sys_perf_event_open', PTR, NUMERIC, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_mmap2 = SyscallDef('sys_mmap2', PTR, NUMERIC, NUMERIC, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_old_mmap = SyscallDef('sys_mmap', PTR)  #:
    sys_name_to_handle_at = SyscallDef('sys_name_to_handle_at', NUMERIC, CHARP, PTR, PTR, NUMERIC)  #:
    sys_open_by_handle_at = SyscallDef('sys_open_by_handle_at', NUMERIC, PTR, NUMERIC)  #:
    sys_setns = SyscallDef('sys_setns', NUMERIC, NUMERIC)  #:
    sys_process_vm_readv = SyscallDef('sys_process_vm_readv', NUMERIC, PTR, NUMERIC, PTR, NUMERIC, NUMERIC)  #:
    sys_process_vm_writev = SyscallDef('sys_process_vm_writev', NUMERIC, PTR, NUMERIC, PTR, NUMERIC, NUMERIC)  #:
    sys_kcmp = SyscallDef('sys_kcmp', NUMERIC, NUMERIC, NUMERIC, NUMERIC, NUMERIC)  #:
    sys_finit_module = SyscallDef('sys_finit_module', NUMERIC, CHARP, NUMERIC)  #:
    sys_seccomp = SyscallDef('sys_seccomp', NUMERIC, NUMERIC, CHARP)  #:
    sys_getrandom = SyscallDef('sys_getrandom', CHARP, NUMERIC, NUMERIC)  #:
    sys_bpf = SyscallDef('sys_bpf', NUMERIC, PTR, NUMERIC)  #:
    sys_execveat = SyscallDef('sys_execveat', NUMERIC, CHARP, CHARPP, CHARPP, NUMERIC)  #:
    sys_membarrier = SyscallDef('sys_membarrier', NUMERIC, NUMERIC)  #:
    sys_copy_file_range = SyscallDef('sys_copy_file_range', NUMERIC, PTR, NUMERIC, PTR, NUMERIC, NUMERIC)  #:
    sys_mlock2 = SyscallDef('sys_mlock2', NUMERIC, NUMERIC, NUMERIC)  #:

    @property
    def SYSCALL_ARG_MAP(self):
        raise NotImplementedError('Target does not define a syscall argument mapping')

    @property
    def SYSCALL_REG(self):
        raise NotImplementedError('Target does not define a syscall register')

    @property
    def SYSCALL_INSTR(self):
        raise NotImplementedError('Target does not define a syscall instruction')

    @property
    def SYSCALL_MAP(self):
        raise NotImplementedError('Target does not define a syscall mapping')

    def syscall(self, op):
        code = []

        def handle_arg(reg, arg):
            if isinstance(arg, SyscallInvoke):
                code.extend(
                    self.syscall(arg) +
                    self.reg_push(self.SYSCALL_RET_REG)
                )
                return self.reg_pop(reg)
            else:
                return self.reg_load(reg, arg)

        arg_code = []
        for arg_reg, arg_value in reversed(list(zip(self.SYSCALL_ARG_MAP, op.args))):
            arg_code.extend(handle_arg(arg_reg, arg_value))
        code.extend(arg_code)

        return code + \
            self.reg_load(self.SYSCALL_REG, self.SYSCALL_MAP[op.syscall_def]) + \
            [self.SYSCALL_INSTR]

    def __init__(self, *args, **kwargs):
        super(Linux, self).__init__(*args, **kwargs)

        # Compatibility back-fills
        if self.sys_socketcall in self.SYSCALL_MAP:
            def gen_socketcall_wrap(socketcall_nr):
                return lambda *args: self.sys_socketcall(socketcall_nr, list(args))

            for syscall_name, socketcall_nr in (
                ('sys_socket', 1),
                ('sys_bind', 2),
                ('sys_connect', 3),
                ('sys_listen', 4),
                ('sys_accept', 5),
                ('sys_getsockname', 6),
                ('sys_getpeername', 7),
                ('sys_socketpair', 8),
                ('sys_send', 9),
                ('sys_recv', 10),
                ('sys_sendto', 11),
                ('sys_recvfrom', 12),
                ('sys_shutdown', 13),
                ('sys_setsockopt', 14),
                ('sys_getsockopt', 15),
                ('sys_sendmsg', 16),
                ('sys_recvmsg', 17),
                ('sys_accept4', 18),
            ):
                syscall = getattr(self, syscall_name)
                if not syscall in self.SYSCALL_MAP:
                    setattr(self, syscall_name, gen_socketcall_wrap(socketcall_nr))

        if self.sys_dup2 not in self.SYSCALL_MAP and self.sys_dup3 in self.SYSCALL_MAP:
            self.sys_dup2 = lambda old_fd, new_fd: self.sys_dup3(old_fd, new_fd, 0)

        if self.sys_accept not in self.SYSCALL_MAP and self.sys_accept4 in self.SYSCALL_MAP:
            self.sys_accept = lambda *args: self.sys_accept4(*(args + (0,)))
