from pwnypack.asm import asm
from pwnypack.shellcode.arm import ARM

__all__ = [ 'ARMThumb' ]

class ARMThumb(ARM):
    @property
    def PREAMBLE(self):
        return [
            '.global _start',
            self.ARCH_SET_TYPE,
            '_start:'
        ]

    def reg_add_imm(self, reg, value):
        if not value:
            return []
        elif value < 2:
            return ['inc %s' % reg] * value
        else:
            return self.reg_load_imm(self.TEMP_REG2, value) + ['add %s, %s' % (reg, self.TEMP_REG2) ]

    def reg_load_offset(self, reg, value):
        if value == 0:
            return self.reg_load_reg(reg, self.OFFSET_REG)
        else:
            return self.reg_load_imm(self.TEMP_REG2, value) + [ 'add %s, %s, %s' % (reg, self.OFFSET_REG, self.TEMP_REG2) ]

