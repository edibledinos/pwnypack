.. _imperative-shellcode:

Imperatively defined shellcode
==============================

When using the imperatively defined shellcode, you translate a python function
to a set of shellcode primitives.

The set of operations you can use in your python function is limited. The
properties of the environment (syscalls, registers, functions) are exposed
as if they were globals.

You translate a function by using the environment's ``translate`` class
method.

Examples:

    The following example creates an instance of the LinuxX86 environment
    and assembles a piece of shellcode that just calls the exit system call.

    >>> from pwny import *
    >>> @sc.LinuxX86.translate()
    ... def shellcode():
    ...     sys_exit(0)
    ...
    >>> shellcode()
    '1\xdb\xb8\x01\x00\x00\x00\xcd\x80'

    To demonstrate how registers loading works, here's an example that does
    the same thing but in a different way:

    >>> from pwny import *
    >>> @sc.LinuxX86.translate()
    ... def shellcode():
    ...     EAX = 0
    ...     sys_exit(EAX)
    ...
    >>> shellcode()
    '1\xc0\x89\xc3\xb8\x01\x00\x00\x00\xcd\x80'

    You can also use strings or bytes. If you use a unicode string, it will
    be UTF-8 encoded and zero-terminated. Bytes are allocated verbatim.

    >>> from pwny import *
    >>> @sc.LinuxX86.translate()
    ... def shellcode():
    ...     sys_write(1, u'hello', 5)
    ...     sys_exit(0)
    ...
    >>> shellcode()
    '\xe8\x00\x00\x00\x00]\x83\xc5 \xba\x05\x00\x00\x00\x89\xe9\xbb\x01\x00\x00\x00\xb8\x04\x00\x00\x00\xcd\x801\xdb\xb8\x01\x00\x00\x00\xcd\x80hello\x00'

    Or use lists as syscall arguments.

    >>> from pwny import *
    >>> @sc.LinuxX86.translate()
    ... def shellcode():
    ...     sys_execve(u'/bin/sh', [u'/bin/sh', None], None)
    ...
    >>> shellcode()
    '\xe8\x00\x00\x00\x00]\x83\xc5\x151\xd21\xc0PU\x89\xe1\x89\xeb\xb8\x0b\x00\x00\x00\xcd\x80/bin/sh\x00'

    Need a buffer to write something to? We've got you covered.

    >>> from pwny import *
    >>> @sc.LinuxX86.translate()
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
    >>> @sc.LinuxX86.translate()
    ... def shellcode(command):
    ...     sys_execve(u'/bin/sh', [u'/bin/sh', command, None], None)
    ...
    >>> shellcode(u'ls -lR')
    '\xe8\x00\x00\x00\x00]\x83\xc5\x1a1\xd21\xc0PU\x8dE\x07P\x89\xe1\x8d]\x07\xb8\x0b\x00\x00\x00\xcd\x80ls -lR\x00/bin/sh\x00'
