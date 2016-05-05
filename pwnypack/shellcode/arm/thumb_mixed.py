from pwnypack.shellcode.arm.thumb import ARMThumb


__all__ = ['ARMThumbMixed']


class ARMThumbMixed(ARMThumb):
    """
    Environment that targets a generic, unrestricted ARM architecture that
    switches to the Thumb instruction set.
    """

    PREAMBLE = [
        '.global _start',
        '.arm',
        '_start:',
        '\tadd r0, pc, #1',
        '\tbx r0',
        '.thumb',
        '__thumbcode:',
    ]
