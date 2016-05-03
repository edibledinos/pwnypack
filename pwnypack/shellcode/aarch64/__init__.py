from pwnypack.shellcode.base import BaseEnvironment
from pwnypack.shellcode.types import Register
from pwnypack.target import Target


__all__ = ['AArch64']


class AArch64(BaseEnvironment):
    """
    Environment that targets a generic, unrestricted AArch64 architecture.
    """

    target = None  #: Target architecture, initialized in __init__.

    X0 = Register('x0')  #: x0 register
    X1 = Register('x1')  #: x1 register
    X2 = Register('x2')  #: x2 register
    X3 = Register('x3')  #: x3 register
    X4 = Register('x4')  #: x4 register
    X5 = Register('x5')  #: x5 register
    X6 = Register('x6')  #: x6 register
    X7 = Register('x7')  #: x7 register
    X8 = Register('x8')  #: x8 register
    X9 = Register('x9')  #: x9 register
    X10 = Register('x10')  #: x10 register
    X11 = Register('x11')  #: x11 register
    X12 = Register('x12')  #: x12 register
    X13 = Register('x13')  #: x13 register
    X14 = Register('x14')  #: x14 register
    X15 = Register('x15')  #: x15 register
    X16 = Register('x16')  #: x16 register
    X17 = Register('x17')  #: x17 register
    X18 = Register('x18')  #: x18 register
    X19 = Register('x19')  #: x19 register
    X20 = Register('x20')  #: x20 register
    X21 = Register('x21')  #: x21 register
    X22 = Register('x22')  #: x22 register
    X23 = Register('x23')  #: x23 register
    X24 = Register('x24')  #: x24 register
    X25 = Register('x25')  #: x25 register
    X26 = Register('x26')  #: x26 register
    X27 = Register('x27')  #: x27 register
    X28 = Register('x28')  #: x28 register
    X29 = Register('x29')  #: x29 register
    X30 = Register('x30')  #: x30 register

    W0 = Register('w0')  #: w0 register
    W1 = Register('w1')  #: w1 register
    W2 = Register('w2')  #: w2 register
    W3 = Register('w3')  #: w3 register
    W4 = Register('w4')  #: w4 register
    W5 = Register('w5')  #: w5 register
    W6 = Register('w6')  #: w6 register
    W7 = Register('w7')  #: w7 register
    W8 = Register('w8')  #: w8 register
    W9 = Register('w9')  #: w9 register
    W10 = Register('w10')  #: w10 register
    W11 = Register('w11')  #: w11 register
    W12 = Register('w12')  #: w12 register
    W13 = Register('w13')  #: w13 register
    W14 = Register('w14')  #: w14 register
    W15 = Register('w15')  #: w15 register
    W16 = Register('w16')  #: w16 register
    W17 = Register('w17')  #: w17 register
    W18 = Register('w18')  #: w18 register
    W19 = Register('w19')  #: w19 register
    W20 = Register('w20')  #: w20 register
    W21 = Register('w21')  #: w21 register
    W22 = Register('w22')  #: w22 register
    W23 = Register('w23')  #: w23 register
    W24 = Register('w24')  #: w24 register
    W25 = Register('w25')  #: w25 register
    W26 = Register('w26')  #: w26 register
    W27 = Register('w27')  #: w27 register
    W28 = Register('w28')  #: w28 register
    W29 = Register('w29')  #: w29 register
    W30 = Register('w30')  #: w30 register

    SP = Register('sp')  #: sp (stack pointer) register
    XZR = Register('xzr')  #: xzr register
    WZR = Register('wzr')  #: wzr register

    STACK_REG = SP
    OFFSET_REG = X29
    TEMP_REG = {64: X8, 32: W8}

    PREAMBLE = [
        '.global _start',
        '_start:',
    ]

    REGISTER_WIDTH_MAP = {
        64: [X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, X16, X17, X18, X19, X20, X21,
             X22, X23, X24, X25, X26, X27, X28, X29, X30, SP, XZR],
        32: [W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15, W16, W17, W18, W19, W20, W21,
             W22, W23, W24, W25, W26, W27, W28, W29, W30, WZR]
    }

    def __init__(self, endian=None, *args, **kwargs):
        self.target = Target(Target.Arch.arm, 64, endian)
        super(AArch64, self).__init__(*args, **kwargs)

    def reg_push(self, reg):
        return ['str %s, [sp, #-%d]!' % (reg, self.REGISTER_WIDTH[reg] // 8)]

    def reg_pop(self, reg):
        return ['ldr %s, [sp], #%d' % (reg, self.REGISTER_WIDTH[reg] // 8)]

    def reg_add_imm(self, reg, imm):
        if imm <= 4096:
            return ['add %s, %s, #%d' % (reg, reg, imm)]

        temp_reg = self.TEMP_REG[self.REGISTER_WIDTH[reg]]
        if reg is temp_reg:
            raise ValueError('Cannot perform large reg_add on temporary register')

        return ['ldr %s, =%d' % (temp_reg, imm),
                'add %s, %s, %s' % (reg, reg, temp_reg)]

    def reg_sub_imm(self, reg, imm):
        if imm <= 4096:
            return ['sub %s, %s, #%d' % (reg, reg, imm)]

        temp_reg = self.TEMP_REG[self.REGISTER_WIDTH[reg]]
        if reg is temp_reg:
            raise ValueError('Cannot perform large reg_add on temporary register')

        return ['ldr %s, =%d' % (temp_reg, imm),
                'sub %s, %s, %s' % (reg, reg, temp_reg)]

    def reg_add_reg(self, reg1, reg2):
        return ['add %s, %s, %s' % (reg1, reg1, reg2)]

    def reg_sub_reg(self, reg1, reg2):
        return ['sub %s, %s, %s' % (reg1, reg1, reg2)]

    def reg_load_imm(self, reg, value):
        if not value:
            return ['eor %s, %s, %s' % (reg, reg, reg)]
        elif value < 0xff:
            return ['mov %s, #%d' % (reg, value)]
        else:
            return ['ldr %s, =%d' % (reg, value)]

    def reg_load_reg(self, dest_reg, src_reg):
        return ['mov %s, %s' % (dest_reg, src_reg)]

    def reg_load_offset(self, reg, value):
        return ['add %s, %s, #%d' % (reg, self.OFFSET_REG, value)]

    def jump_reg(self, reg):
        return ['br %s' % reg]
