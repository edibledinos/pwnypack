import six

from pwnypack.shellcode.base import BaseEnvironment
from pwnypack.shellcode.types import Register
from pwnypack.target import Target


__all__ = ['AArch64']


class AArch64(BaseEnvironment):
    """
    Environment that targets a generic, unrestricted AArch64 architecture.
    """

    target = None  #: Target architecture, initialized in __init__.

    X0 = Register('x0')
    X1 = Register('x1')
    X2 = Register('x2')
    X3 = Register('x3')
    X4 = Register('x4')
    X5 = Register('x5')
    X6 = Register('x6')
    X7 = Register('x7')
    X8 = Register('x8')
    X9 = Register('x9')
    X10 = Register('x10')
    X11 = Register('x11')
    X12 = Register('x12')
    X13 = Register('x13')
    X14 = Register('x14')
    X15 = Register('x15')
    X16 = Register('x16')
    X17 = Register('x17')
    X18 = Register('x18')
    X19 = Register('x19')
    X20 = Register('x20')
    X21 = Register('x21')
    X22 = Register('x22')
    X23 = Register('x23')
    X24 = Register('x24')
    X25 = Register('x25')
    X26 = Register('x26')
    X27 = Register('x27')
    X28 = Register('x28')
    X29 = Register('x29')
    X30 = Register('x30')

    W0 = Register('w0')
    W1 = Register('w1')
    W2 = Register('w2')
    W3 = Register('w3')
    W4 = Register('w4')
    W5 = Register('w5')
    W6 = Register('w6')
    W7 = Register('w7')
    W8 = Register('w8')
    W9 = Register('w9')
    W10 = Register('w10')
    W11 = Register('w11')
    W12 = Register('w12')
    W13 = Register('w13')
    W14 = Register('w14')
    W15 = Register('w15')
    W16 = Register('w16')
    W17 = Register('w17')
    W18 = Register('w18')
    W19 = Register('w19')
    W20 = Register('w20')
    W21 = Register('w21')
    W22 = Register('w22')
    W23 = Register('w23')
    W24 = Register('w24')
    W25 = Register('w25')
    W26 = Register('w26')
    W27 = Register('w27')
    W28 = Register('w28')
    W29 = Register('w29')
    W30 = Register('w30')

    SP = Register('sp')
    XZR = Register('xzr')
    WZR = Register('wzr')

    STACK_REG = SP
    OFFSET_REG = X29
    TEMP_REG = {64: X8, 32: W8}

    PREAMBLE = [
        '.global _start',
        '_start:',
    ]

    GETPC = [
        '\tadr %s, __data' % OFFSET_REG,
        '__realstart:'
    ]

    REGISTER_WIDTH_MAP = {
        64: [X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, X16, X17, X18, X19, X20, X21,
             X22, X23, X24, X25, X26, X27, X28, X29, X30, SP, XZR],
        32: [W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15, W16, W17, W18, W19, W20, W21,
             W22, W23, W24, W25, W26, W27, W28, W29, W30, WZR]
    }

    def __init__(self, endian=None):
        self.target = Target(Target.Arch.arm, 64, endian)
        super(AArch64, self).__init__()

    def reg_push(self, reg):
        return ['str %s, [sp, #-%d]!' % (reg, self.REGISTER_WIDTH[reg] // 8)]

    def reg_pop(self, reg):
        return ['ldr %s, [sp], #%d' % (reg, self.REGISTER_WIDTH[reg] // 8)]

    def reg_load_imm(self, reg, value):
        if not value:
            return ['eor %s, %s, %s' % (reg, reg, reg)]
        elif value < 0xff:
            return ['mov %s, #0x%x' % (reg, value)]
        else:
            return ['ldr %s, =0x%x' % (reg, value)]

    def reg_load_reg(self, dest_reg, src_reg):
        return ['mov %s, %s' % (dest_reg, src_reg)]

    def reg_load_offset(self, reg, value):
        return ['add %s, %s, #%d' % (reg, self.OFFSET_REG, value)]

    def finalize_data(self, data):
        if data:
            return ['', '.pool', '.align', '__data:'] + [
                '\t.byte %s  // %r' % (
                    ', '.join(hex(b) for b in six.iterbytes(datum)),
                    orig_datum,
                )
                for datum, (_, orig_datum) in six.iteritems(data)
            ]
        else:
            return ['', '.pool']

    def finalize(self, code, data):
        return self.PREAMBLE + \
            (self.GETPC if data else []) + \
            ['\t%s' % line for line in code] + \
            self.finalize_data(data)
