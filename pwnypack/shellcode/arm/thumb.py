from pwnypack.shellcode.arm import ARM


__all__ = ['ARMThumb']


class ARMThumb(ARM):
    ARCH_SET_TYPE = '.thumb'

    def reg_load_offset(self, reg, value):
        if value == 0:
            return self.reg_load_reg(reg, self.OFFSET_REG)
        else:
            return self.reg_load_imm(self.TEMP_REG2, value) + \
                   ['add %s, %s, %s' % (reg, self.OFFSET_REG, self.TEMP_REG2)]
