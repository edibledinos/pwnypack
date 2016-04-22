import six

from pwnypack.shellcode.base import BaseEnvironment
from pwnypack.shellcode.types import Register
from pwnypack.target import Target


__all__ = ['ARM']


class ARM(BaseEnvironment):
    """
    Environment that targets a generic, unrestricted ARM architecture.
    """

    target = None  #: Target architecture, initialized in __init__.

    R0 = Register('r0')
    R1 = Register('r1')
    R2 = Register('r2')
    R3 = Register('r3')
    R4 = Register('r4')
    R5 = Register('r5')
    R6 = Register('r6')
    R7 = Register('r7')
    R8 = Register('r8')
    R9 = Register('r9')
    R10 = Register('r10')
    R11 = Register('r11')
    R12 = Register('r12')
    SP = Register('sp')
    LR = Register('lr')
    PC = Register('pc')

    REGISTER_WIDTH_MAP = {
        32: [R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, SP, LR, PC]
    }

    STACK_REG = SP
    OFFSET_REG = R6
    TEMP_REG = {32: R7}

    PREAMBLE = [
        '.global _start',
        '_start:',
    ]

    GETPC = [
        '\tadr %s, __data' % OFFSET_REG,
        '__realstart:'
    ]

    def __init__(self, endian=None):
        self.target = Target(Target.Arch.arm, 32, endian)
        super(ARM, self).__init__()

    def reg_push(self, reg):
        return ['push {%s}' % reg]

    def reg_pop(self, reg):
        return ['pop {%s}' % reg]

    def reg_load_imm(self, reg, value):
        if not value:
            return ['eor %s, %s' % (reg, reg)]
        elif value < 0xff:
            return ['mov %s, #0x%x' % (reg, value)]
        else:
            return ['ldr %s, =0x%x' % (reg, value)]

    def reg_load_reg(self, dest_reg, src_reg):
        return ['mov %s, %s' % (dest_reg, src_reg)]

    def reg_load_offset(self, reg, value):
       return ['add %s, %s, #%d' % (reg, self.OFFSET_REG, value)]

    def finalize_data(self, data):
        return ['', '.pool', '.align', '__data:'] + [
            '\t.byte %s  @ %r' % (
                ', '.join(hex(b) for b in six.iterbytes(datum)),
                orig_datum,
            )
            for datum, (_, orig_datum) in six.iteritems(data)
        ]

    def finalize(self, code, data):
        return self.PREAMBLE + \
            self.GETPC + \
            ['\t%s' % line for line in code] + \
            self.finalize_data(data)
