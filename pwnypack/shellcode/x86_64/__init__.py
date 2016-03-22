from pwnypack.shellcode.types import Register
from pwnypack.shellcode.x86 import X86
from pwnypack.target import Target


__all__ = ['X86_64']


class X86_64(X86):
    target = Target(arch=Target.Arch.x86, bits=64)

    # 8-bit registers on X86_64
    R8B = Register('r8b')
    R9B = Register('r9b')
    R10B = Register('r10b')
    R11B = Register('r11b')
    R12B = Register('r12b')
    R13B = Register('r13b')
    R14B = Register('r14b')
    R15B = Register('r15b')

    # 16-bit registers on X86_64
    R8W = Register('r8w')
    R9W = Register('r9w')
    R10W = Register('r10w')
    R11W = Register('r11w')
    R12W = Register('r12w')
    R13W = Register('r13w')
    R14W = Register('r14w')
    R15W = Register('r15w')

    # 32-bit registers on X86_64
    R8D = Register('r8d')
    R9D = Register('r9d')
    R10D = Register('r10d')
    R11D = Register('r11d')
    R12D = Register('r12d')
    R13D = Register('r13d')
    R14D = Register('r14d')
    R15D = Register('r16d')

    # 64-bit registers on X86_64
    RAX = Register('rax')
    RBX = Register('rbx')
    RCX = Register('rcx')
    RDX = Register('rdx')
    RSI = Register('rsi')
    RDI = Register('rdi')
    RSP = Register('rsp')
    RBP = Register('rbp')
    RIP = Register('rip')
    R8 = Register('r8')
    R9 = Register('r9')
    R10 = Register('r10')
    R11 = Register('r11')
    R12 = Register('r12')
    R13 = Register('r13')
    R14 = Register('r14')
    R15 = Register('r15')

    TEMP_REG = X86.TEMP_REG.copy()
    TEMP_REG[64] = RAX

    TEMP_PTR = TEMP_REG[64]
    PC = RIP
    OFFSET_REG = RBP
    STACK_REG = RSP

    REGISTER_WIDTH_MAP = X86.REGISTER_WIDTH_MAP.copy()
    REGISTER_WIDTH_MAP[8] += (R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B)
    REGISTER_WIDTH_MAP[16] += (R8D, R9D, R10D, R11D, R12D, R13D, R14D, R15D)
    REGISTER_WIDTH_MAP[32] += (R8W, R9W, R10W, R11W, R12W, R13W, R14W, R15W)
    REGISTER_WIDTH_MAP[64] = (RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8, R9, R10, R11, R12, R13, R14, R15)
