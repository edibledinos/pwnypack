from pwnypack.shellcode.x86.null_safe_mutable import X86NullSafeMutable
from pwnypack.shellcode.x86_64.null_safe import X86_64NullSafe


__all__ = ['X86_64NullSafeMutable']


class X86_64NullSafeMutable(X86_64NullSafe, X86NullSafeMutable):
    pass
