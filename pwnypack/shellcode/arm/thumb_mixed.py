from pwnypack.shellcode.arm.thumb import ARMThumb


__all__ = ['ARMThumbMixed']


class ARMThumbMixed(ARMThumb):
    @property
    def PREAMBLE(self):
        return [
            '.global _start',
            '.arm',
            '_start:',
            '\tadr r0, __thumbcode',
            '\tadd r0, #1',
            '\tbx r0',
            self.ARCH_SET_TYPE,
            '__thumbcode:',
        ]
