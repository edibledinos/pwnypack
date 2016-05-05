from pwnypack.shellcode.arm import ARM
from pwnypack.target import Target


__all__ = ['ARMThumb']


class ARMThumb(ARM):
    """
    Environment that targets a generic, unrestricted ARM architecture using
    the Thumb instruction set.
    """

    def __init__(self, endian=None, *args, **kwargs):
        super(ARMThumb, self).__init__(endian, *args, **kwargs)
        self.target.mode |= Target.Mode.arm_thumb

    def reg_add_imm(self, reg, value):
        if value < 256:
            return ['add %s, #%d' % (reg, value)]

        temp_reg = self.TEMP_REG[self.REGISTER_WIDTH[reg]]
        if reg is temp_reg:
            raise ValueError('Cannot perform large reg_add on temporary register')

        return ['ldr %s, =%d' % (temp_reg, value),
                'add %s, %s' % (temp_reg, reg),
                'mov %s, %s' % (reg, temp_reg)]

    def reg_sub_imm(self, reg, value):
        if value < 256:
            return ['sub %s, #%d' % (reg, value)]

        temp_reg = self.TEMP_REG[self.REGISTER_WIDTH[reg]]
        if reg is temp_reg:
            raise ValueError('Cannot perform large reg_add on temporary register')

        return ['ldr %s, =%d' % (temp_reg, -value),
                'add %s, %s' % (temp_reg, reg),
                'mov %s, %s' % (reg, temp_reg)]

    def reg_load_imm(self, reg, value):
        if -256 < value < 0:
            return ['mov %s, #%d' % (reg, -value),
                    'neg %s, %s' % (reg, reg)]
        else:
            return super(ARMThumb, self).reg_load_imm(reg, value)

    def reg_load_offset(self, reg, value):
        return self.reg_load_imm(reg, value) + \
               ['add %s, %s' % (reg, self.OFFSET_REG)]
