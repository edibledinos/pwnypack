from pwnypack.asm import asm
from pwnypack.shellcode.arm.thumb import ARMThumb

__all__ = [ 'ARMThumbMixed' ]

class ARMThumbMixed(ARMThumb):
    @property
    def PREAMBLE(self):
        return [
            '.global _start',
            '.arm',
            '_start:',
            'adr r0,__thumbcode',
            'add r0,#1',
            'bx r0',
            self.ARCH_SET_TYPE,
            '__thumbcode:'
        ]
