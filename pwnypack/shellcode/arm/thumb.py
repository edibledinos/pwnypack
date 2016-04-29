from pwnypack.shellcode.arm import ARM
from pwnypack.target import Target


__all__ = ['ARMThumb']


class ARMThumb(ARM):
    def __init__(self, endian=None):
        super(ARMThumb, self).__init__(endian)
        self.target.mode |= Target.Mode.arm_thumb

    def reg_add_imm(self, reg, value):
        return ['add %s, #%d' % (reg, value)]

    def reg_sub_imm(self, reg, value):
        return ['sub %s, #%d' % (reg, value)]

    def reg_load_imm(self, reg, value):
        if -256 < value < 0:
            return ['mov %s, #%d' % (reg, -value),
                    'neg %s, %s' % (reg, reg)]
        else:
            return super(ARMThumb, self).reg_load_imm(reg, value)

    def reg_load_offset(self, reg, value):
        return self.reg_load_imm(reg, value) + \
               ['add %s, %s' % (reg, self.OFFSET_REG)]
