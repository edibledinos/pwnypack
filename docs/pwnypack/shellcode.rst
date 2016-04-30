:mod:`~pwnypack.shellcode` -- Shellcode generator
=================================================

This module contains functions to generate shellcode.

Note:
    The intended audience for this documentation is the user. Implementation
    details are left out where possible.

The idea is that you provide a shellcode generator environment with a
highlevel declarative representation of the shellcode your want to
assemble and the environment fills in the specifics.

The generic environments target X86, X86_64, ARM, ARM Thumb, ARM Thumb
Mixed and AArch64 on the Linux OS. No restrictions are made on what kind of
bytes end up in the binary output. If you use buffers, the code segment will
need to be writable if you use the ``Mutable`` variants. The ``Stack``
variants require an initialized stack that is large enough to hold all the
allocated data and buffers.

X86:

- :class:`~pwnypack.shellcode.x86.linux.LinuxX86Mutable`
- :class:`~pwnypack.shellcode.x86.linux.LinuxX86Stack`

X86_64:

- :class:`~pwnypack.shellcode.x86_64.linux.LinuxX86_64Mutable`
- :class:`~pwnypack.shellcode.x86_64.linux.LinuxX86_64Stack`

ARM:

- :class:`~pwnypack.shellcode.arm.linux.LinuxARMMutable`
- :class:`~pwnypack.shellcode.arm.linux.LinuxARMStack`

ARM Thumb:

- :class:`~pwnypack.shellcode.arm.linux.LinuxARMThumbMutable`
- :class:`~pwnypack.shellcode.arm.linux.LinuxARMThumbStack`

ARM with modeswitch to Thumb mode:

- :class:`~pwnypack.shellcode.arm.linux.LinuxARMThumbMixed`
- :class:`~pwnypack.shellcode.arm.linux.LinuxARMThumbStack`

AArch64:

- :class:`~pwnypack.shellcode.aarch64.linux.LinuxAArch64Mutable`
- :class:`~pwnypack.shellcode.aarch64.linux.LinuxAArch64Stack`

Specialized classes are also provided for X86 and X86_64. The
*NullSafeMutable* and *NullSafeStack* variants attempt to generate binary
output that does not contain NUL bytes, carriage returns and line feeds.

X86:

- :class:`~pwnypack.shellcode.x86.linux.LinuxX86MutableNullSafe`
- :class:`~pwnypack.shellcode.x86.linux.LinuxX86StackNullSafe`

X86_64:

- :class:`~pwnypack.shellcode.x86_64.linux.LinuxX86_64MutableNullSafe`
- :class:`~pwnypack.shellcode.x86_64.linux.LinuxX86_64StackNullSafe`

Each shellcode environment defines a set of registers that are available on
the architecture and a set of system calls. These are available as properties
of the respective environment.

The environment also provides a way to allocate strings and buffers. If you
call :meth:`~pwnypack.shellcode.base.BaseEnvironment.alloc_data` with a
bytestring (``str`` on python 2, ``bytes`` on python 3) it will be allocated
verbatim and an :class:`~pwnypack.shellcode.types.Offset` is returned. If
:meth:`~pwnypack.shellcode.base.BaseEnvironment.alloc_data` is called with
a unicode string (``unicode`` on python 2, ``str`` on python 3) it will be
converted to a latin1 based bytestring and terminated with a NUL byte (`\\0`).

:meth:`~pwnypack.shellcode.base.BaseEnvironment.alloc_buffer` can be used to
allocate an uninitialized block of memory. It will not be embedded in the
shellcode.

There are two ways to use these shellcode environments:

- :ref:`Declaratively <declarative-shellcode>`.
- :ref:`Imperatively <imperative-shellcode>`.


.. toctree::
   :hidden:

   shellcode/declarative
   shellcode/imperative

   LinuxX86 <shellcode/x86_linux>
   LinuxX86_64 <shellcode/x86_64_linux>
   LinuxARM <shellcode/arm_linux>
   LinuxAArch64 <shellcode/aarch64_linux>

   X86 <shellcode/x86>
   X86_64 <shellcode/x86_64>
   ARM <shellcode/arm>
   AArch64 <shellcode/aarch64>
   Linux <shellcode/linux>

   Base <shellcode/base>
   Python translator <shellcode/translate>
