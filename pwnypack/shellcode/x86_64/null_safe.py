from pwnypack.shellcode.x86.null_safe import X86NullSafe
from pwnypack.shellcode.x86_64 import X86_64


__all__ = ['X86_64NullSafe']


class X86_64NullSafe(X86_64, X86NullSafe):
    HALF_REG = X86NullSafe.HALF_REG.copy()

    for pair in ((X86_64.RAX, X86_64.EAX), (X86_64.RBX, X86_64.EBX), (X86_64.RCX, X86_64.ECX), (X86_64.RDX, X86_64.EDX),
                 (X86_64.RSI, X86_64.ESI), (X86_64.RDI, X86_64.EDI), (X86_64.RBP, X86_64.EBP), (X86_64.RSP, X86_64.ESP),
                 (X86_64.R8, X86_64.R8D, X86_64.R8W, X86_64.R8B),
                 (X86_64.R9, X86_64.R9D, X86_64.R9W, X86_64.R9B),
                 (X86_64.R10, X86_64.R10D, X86_64.R10W, X86_64.R10B),
                 (X86_64.R11, X86_64.R11D, X86_64.R11W, X86_64.R11B),
                 (X86_64.R12, X86_64.R12D, X86_64.R12W, X86_64.R12B),
                 (X86_64.R13, X86_64.R13D, X86_64.R13W, X86_64.R13B),
                 (X86_64.R14, X86_64.R14D, X86_64.R14W, X86_64.R14B),
                 (X86_64.R15, X86_64.R15D, X86_64.R15W, X86_64.R15B)):
        for reg, half in zip(pair, pair[1:]):
            HALF_REG[reg] = half
    del pair, reg, half
