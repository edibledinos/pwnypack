import six

from pwnypack.shellcode.base import BaseEnvironment
from pwnypack.shellcode.types import Register, Offset
from pwnypack.target import Target

import struct

__all__ = ['ARM']

class ARM(BaseEnvironment):
    """
    Environment that targets a generic, unrestricted ARM architecture.
    """

    target = Target(arch=Target.Arch.arm, bits=32)  #: Target architecture

    R0 = Register('r0')
    R1 = Register('r1')
    R2 = Register('r2')
    R3 = Register('r3')
    R4 = Register('r4')
    R5 = Register('r5')
    R6 = Register('r6')
    R7 = Register('r7')
    R8 = Register('r8')
    SP = Register('sp')

    OFFSET_REG = R5
    TEMP_REG = R6
    TEMP_REG2 = R4
    SYSCALL_REG = R7
    STACK_REG = SP

    @property
    def PREAMBLE(self):
        return [
            '.global _start',
            '',
            self.ARCH_SET_TYPE,
            '_start:',
        ]

    @property
    def GETPC(self):
        return [
            '__getpc0:',
            'adr %s, __data' % self.OFFSET_REG.name,
            '__realstart:'
        ]

    def __init__(self):
        super(ARM, self).__init__()

    def reg_push(self, reg):
        return ['push {%s}' % reg]

    def reg_pop(self, reg):
        return ['pop {%s}' % reg]

    def reg_add_reg(self, reg, add_reg):
        return ['add %s, %s' % (reg, add_reg)]

    def reg_add_imm(self, reg, value):
        if not value:
            return []
        elif value < 2:
            return ['inc %s' % reg] * value
        else:
            return ['add %s, %d' % (reg, value)]

    def reg_load_imm(self, reg, value):
        if not value:
            return [ "eor %s, %s" % (reg, reg) ]
        if value < 0xff:
            return [ "mov %s, #0x%x" % (reg, value) ]
        else:
            offs = self.alloc_data(U32(value, target=self.target))
            dkey = "data_%08x" % offs

            return ['ldr %s, %s' % (reg, dkey)]

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
        o = ['.pool', '__data:']
        pos = 0
        for datum, (_, orig_datum) in six.iteritems(data):
            dv = '\t.byte ' + b', '.join(hex(b) for b in six.iterbytes(datum))
            o.append("data_%08x:" % pos)
            o.append(dv)
            pos = pos + len(datum)

        return o

    def finalize(self, code, data):
        return self.PREAMBLE + \
            (self.GETPC) + \
            ['\t%s' % line for line in code] + \
            self.finalize_data(data)
