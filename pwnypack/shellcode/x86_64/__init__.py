from pwnypack.shellcode.types import Register
from pwnypack.shellcode.x86 import X86
from pwnypack.target import Target


__all__ = ['X86_64']


class X86_64(X86):
    """
    Environment that targets a generic, unrestricted X86_64 architecture.
    """

    target = Target(arch=Target.Arch.x86, bits=64)  #: Target architecture

    # 8-bit registers on X86_64
    R8B = Register('r8b')  #: r8b register
    R9B = Register('r9b')  #: r9b register
    R10B = Register('r10b')  #: r10b register
    R11B = Register('r11b')  #: r11b register
    R12B = Register('r12b')  #: r12b register
    R13B = Register('r13b')  #: r13b register
    R14B = Register('r14b')  #: r14b register
    R15B = Register('r15b')  #: r15b register

    # 16-bit registers on X86_64
    R8W = Register('r8w')  #: r8w register
    R9W = Register('r9w')  #: r9w register
    R10W = Register('r10w')  #: r10w register
    R11W = Register('r11w')  #: r11w register
    R12W = Register('r12w')  #: r12w register
    R13W = Register('r13w')  #: r13w register
    R14W = Register('r14w')  #: r14w register
    R15W = Register('r15w')  #: r15w register

    # 32-bit registers on X86_64
    R8D = Register('r8d')  #: r8d register
    R9D = Register('r9d')  #: r9d register
    R10D = Register('r10d')  #: r10d register
    R11D = Register('r11d')  #: r11d register
    R12D = Register('r12d')  #: r12d register
    R13D = Register('r13d')  #: r13d register
    R14D = Register('r14d')  #: r14d register
    R15D = Register('r16d')  #: r16d register

    # 64-bit registers on X86_64
    RAX = Register('rax')  #: rax register
    RBX = Register('rbx')  #: rbx register
    RCX = Register('rcx')  #: rcx register
    RDX = Register('rdx')  #: rdx register
    RSI = Register('rsi')  #: rsi register
    RDI = Register('rdi')  #: rdi register
    RSP = Register('rsp')  #: rsp register
    RBP = Register('rbp')  #: rbp register
    RIP = Register('rip')  #: rip register
    R8 = Register('r8')  #: r8 register
    R9 = Register('r9')  #: r9 register
    R10 = Register('r10')  #: r10 register
    R11 = Register('r11')  #: r11 register
    R12 = Register('r12')  #: r12 register
    R13 = Register('r13')  #: r13 register
    R14 = Register('r14')  #: r14 register
    R15 = Register('r15')  #: r15 register

    REGISTER_WIDTH_MAP = X86.REGISTER_WIDTH_MAP.copy()
    REGISTER_WIDTH_MAP[8] += (R8B, R9B, R10B, R11B, R12B, R13B, R14B, R15B)
    REGISTER_WIDTH_MAP[16] += (R8D, R9D, R10D, R11D, R12D, R13D, R14D, R15D)
    REGISTER_WIDTH_MAP[32] += (R8W, R9W, R10W, R11W, R12W, R13W, R14W, R15W)
    REGISTER_WIDTH_MAP[64] = (RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8, R9, R10, R11, R12, R13, R14, R15)

    STACK_REG = RSP
    OFFSET_REG = RBP
    TEMP_REG = X86.TEMP_REG.copy()
    TEMP_REG[64] = RAX
