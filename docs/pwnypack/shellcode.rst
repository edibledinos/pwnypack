:mod:`~pwnypack.shellcode` -- Shellcode generator
=================================================

This module contains functions to generate shellcode.

Note:
    The intended audience for this documentation is the user. Implementation
    details are left out where possible.

The idea is that you provide a shellcode generator environment with a
highlevel declarative representation of the shellcode your want to
assemble and the environment fills in the specifics.

Currently, two concrete shellcode environment types exist each in two
different flavors:

The generic environments target X86 and X86_64 on the Linux OS. No
restrictions are made on what kind of bytes end up in the binary output.

- :class:`~pwnypack.shellcode.x86.linux.LinuxX86`
- :class:`~pwnypack.shellcode.x86_64.linux.LinuxX86_64`

Specialized classes are also provided. The *NullSafeMutable* variants
attempt to generate binary output that does not contain NUL bytes, carriage
returns and line feeds.  The shellcode is assumed to be loaded in a mutable
and executable segment (like an executable stack).

- :class:`~pwnypack.shellcode.x86.linux.LinuxX86NullSafeMutable`
- :class:`~pwnypack.shellcode.x86_64.linux.LinuxX86_64NullSafeMutable`

Each shellcode environment defines a set of registers that are available on
the architecture and a set of system calls. These are available as properties
of the respective environment.

The environment also provides a way to allocate buffers

There are two ways to use these shellcode environments:

- :ref:`Declaratively <declarative-shellcode>`.
- :ref:`Imperatively <imperative-shellcode>`.


.. toctree::
   :hidden:

   shellcode/declarative
   shellcode/imperative

   LinuxX86 <shellcode/x86_linux>
   LinuxX86_64 <shellcode/x86_64_linux>

   X86 <shellcode/x86>
   X86_64 <shellcode/x86_64>
   Linux <shellcode/linux>

   Base <shellcode/base>
   Python translator <shellcode/translate>
