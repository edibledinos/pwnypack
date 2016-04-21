import six

from pwnypack.packing import U32
from pwnypack.shellcode.base import BaseEnvironment
from pwnypack.shellcode.types import Register, Offset
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

    OFFSET_REG = R6
    TEMP_REG = R7
    STACK_REG = SP

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

    def reg_add_reg(self, reg, add_reg):
        return ['add %s, %s' % (reg, add_reg)]

    def reg_load_imm(self, reg, value):
        if not value:
            return ['eor %s, %s' % (reg, reg)]
        elif value < 0xff:
            return ['mov %s, #0x%x' % (reg, value)]
        else:
            offset = self.alloc_data(U32(value, target=self.target))
            data_label = 'data_%08x' % offset
            return ['ldr %s, %s' % (reg, data_label)]

    def reg_load_reg(self, dest_reg, src_reg):
        if dest_reg is not src_reg:
            return ['mov %s, %s' % (dest_reg, src_reg)]
        else:
            return []

    def reg_load_offset(self, reg, value):
        if value == 0:
            return self.reg_load_reg(reg, self.OFFSET_REG)
        else:
            return ['add %s, %s, #%d' % (reg, self.OFFSET_REG, value)]

    def reg_load_array(self, reg, value):
        temp_reg = self.TEMP_REG

        code = []
        for item in reversed(value):
            if isinstance(item, (six.text_type, six.binary_type)):
                item = self.alloc_data(item)

            if isinstance(item, Offset) and not item:
                code.extend(self.reg_push(self.OFFSET_REG))
            else:
                code.extend(self.reg_load(temp_reg, item))
                code.extend(self.reg_push(temp_reg))

        code.extend(self.reg_load_reg(reg, self.STACK_REG))
        return code

    def finalize_data(self, data):
        return ['.pool', '__data:'] + [
            'data_%08x:\n\t.byte %s  @ %s' % (
                offset,
                ', '.join(hex(b) for b in six.iterbytes(datum)),
                orig_datum,
            )
            for datum, (offset, orig_datum) in six.iteritems(data)
        ]

    def finalize(self, code, data):
        return self.PREAMBLE + \
            self.GETPC + \
            ['\t%s' % line for line in code] + \
            self.finalize_data(data)
