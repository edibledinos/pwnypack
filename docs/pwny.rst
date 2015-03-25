pwny package
============

The ``pwny`` package provides a convence metapackage that imports the entire
public API of `pwnypack` into a single namespace::

    >>> from pwny import *
    >>> enhex(asm('mov rax, 0xced', target=Target(arch=Architecture.x86_64)))
    u'b8ed0c0000'

For details about what exactly is made available, please consult the
documentation of the individual :doc:`pwnypack modules <pwnypack>`.
