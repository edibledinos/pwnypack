.. _declarative-shellcode:

Declaratively defined shellcode
===============================

When using the declarative method, you create an instance of the shellcode
environment which you then order to translate a list of high level operations.

There are two kinds of operations available:

- :class:`~pwnypack.shellcode.ops.SyscallInvoke`: Invoke a system call. You
  don't generally create your own instances directly. Each environment
  provides access to any available system calls as members which you call
  instead.
- :class:`~pwnypack.shellcode.ops.LoadRegister`: Load a register with a
  given value (which can be a literal value, the memory address of a piece
  of data or a buffer or the result of a system call).

Examples:
    The following example creates an instance of the LinuxX86 environment
    and assembles a piece of shellcode that just calls the exit system call.

    >>> from pwny import *
    >>> env = sc.LinuxX86()
    >>> env.assemble([
    ...     env.sys_exit(0)
    ... ])
    '1\xdb\xb8\x01\x00\x00\x00\xcd\x80'

    To demonstrate how registers loading works, here's an example that does
    the same thing but in a different way:

    >>> from pwny import *
    >>> env = sc.LinuxX86()
    >>> env.assemble([
    ...     sc.LoadRegister(env.EAX, 0),
    ...     env.sys_exit(env.EAX)
    ... ])
    '1\xc0\x89\xc3\xb8\x01\x00\x00\x00\xcd\x80'

    You can also use strings or bytes. If you use a unicode string, it will
    be UTF-8 encoded and zero-terminated. Bytes are allocated verbatim.

    >>> from pwny import *
    >>> env = sc.LinuxX86()
    >>> env.assemble([
    ...     env.sys_write(1, u'hello', 5),
    ...     env.sys_exit(),
    ... ])
    '\xe8\x00\x00\x00\x00]\x83\xc5 \xba\x05\x00\x00\x00\x89\xe9\xbb\x01\x00\x00\x00\xb8\x04\x00\x00\x00\xcd\x801\xdb\xb8\x01\x00\x00\x00\xcd\x80hello\x00'

    Or use lists as syscall arguments.

    >>> from pwny import *
    >>> env = sc.LinuxX86()
    >>> env.assemble([
    ...     env.sys_execve(u'/bin/sh', [u'/bin/sh', None], None)
    ... ])
    '\xe8\x00\x00\x00\x00]\x83\xc5\x151\xd21\xc0PU\x89\xe1\x89\xeb\xb8\x0b\x00\x00\x00\xcd\x80/bin/sh\x00'

    Need a buffer to write something to? We've got you covered.

    >>> from pwny import *
    >>> env = sc.LinuxX86()
    >>> buf = env.alloc_buffer(64)
    >>> env.assemble([
    ...     env.sys_read(0, buf, buf.length),
    ...     env.sys_write(1, buf, buf.length),
    ...     env.sys_exit(0)
    ... ])
    '\xba@\x00\x00\x00\x89\xe91\xdb\xb8\x03\x00\x00\x00\xcd\x80\xba@\x00\x00\x00\x89\xe9\xbb\x01\x00\x00\x00\xb8\x04\x00\x00\x00\xcd\x801\xdb\xb8\x01\x00\x00\x00\xcd\x80'
