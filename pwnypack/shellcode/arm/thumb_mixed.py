from pwnypack.shellcode.arm.thumb import ARMThumb


__all__ = ['ARMThumbMixed']


class ARMThumbMixed(ARMThumb):
    PREAMBLE = [
        '.global _start',
        '.arm',
        '_start:',
        '\tadd r0, pc, #1',
        '\tbx r0',
        '.thumb',
        '__thumbcode:',
    ]
