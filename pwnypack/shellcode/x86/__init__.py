from pwnypack.shellcode.base import BaseEnvironment
from pwnypack.shellcode.types import Register
from pwnypack.target import Target


__all__ = ['X86']


class X86(BaseEnvironment):
    """
    Environment that targets a generic, unrestricted X86 architecture.
    """

    target = Target(arch=Target.Arch.x86, bits=32)  #: Target architecture

    # 8-bit registers on X86
    AL = Register('al')  #: al register
    AH = Register('ah')  #: ah register
    BL = Register('bl')  #: bl register
    BH = Register('bh')  #: bh register
    CL = Register('cl')  #: cl register
    CH = Register('ch')  #: ch register
    DL = Register('dl')  #: dl register
    DH = Register('dh')  #: dh register

    # 16-bit registers on X86
    AX = Register('ax')  #: ax register
    BX = Register('bx')  #: bx register
    CX = Register('cx')  #: cx register
    DX = Register('dx')  #: dx register
    SI = Register('si')  #: si register
    DI = Register('di')  #: di register
    SP = Register('sp')  #: sp register
    BP = Register('bp')  #: bp register
    IP = Register('ip')  #: ip register

    # 32-bit registers on X86
    EAX = Register('eax')  #: eax register
    EBX = Register('ebx')  #: ebx register
    ECX = Register('ecx')  #: ecx register
    EDX = Register('edx')  #: edx register
    ESI = Register('esi')  #: esi register
    EDI = Register('edi')  #: edi register
    ESP = Register('esp')  #: esp register
    EBP = Register('ebp')  #: ebp register
    EIP = Register('eip')  #: eip register

    REGISTER_WIDTH_MAP = {
        8: (AL, BL, CL, DL, AH, BH, CH, DH),
        16: (AX, BX, CX, DX, SI, DI, BP, SP),
        32: (EAX, EBX, ECX, EDX, ESI, EDI, EBP, ESP),
    }

    STACK_REG = ESP
    OFFSET_REG = EBP
    TEMP_REG = {
        32: EAX,
        16: AX,
        8: AL,
    }

    @property
    def PREAMBLE(self):
        return [
            'BITS %d' % self.target.bits.value,
            'global _start',
            '',
            '_start:',
        ]

    def __init__(self, *args, **kwargs):
        super(X86, self).__init__(*args, **kwargs)

    def reg_push(self, reg):
        return ['push %s' % reg]

    def reg_pop(self, reg):
        return ['pop %s' % reg]

    def reg_add_imm(self, reg, value):
        if value == 1:
            return ['inc %s' % reg]
        return ['add %s, %d' % (reg, value)]

    def reg_sub_imm(self, reg, value):
        if value == 1:
            return ['dec %s' % reg]
        return ['sub %s, %d' % (reg, value)]

    def reg_add_reg(self, reg1, reg2):
        return ['add %s, %s' % (reg1, reg2)]

    def reg_sub_reg(self, reg1, reg2):
        return ['sub %s, %s' % (reg1, reg2)]

    def reg_load_imm(self, reg, value):
        reg_width = self.REGISTER_WIDTH[reg]
        if value >= 2 ** reg_width:
            raise ValueError('%d does not fit %s' % (value, reg))

        if not value:
            return ['xor %s, %s' % (reg, reg)]
        else:
            return ['mov %s, %d' % (reg, value)]

    def reg_load_reg(self, dest_reg, src_reg):
        return ['mov %s, %s' % (dest_reg, src_reg)]

    def reg_load_offset(self, reg, value):
        return ['lea %s, [%s + %d]' % (reg, self.OFFSET_REG, value)]

    def jump_reg(self, reg):
        return ['jmp %s' % reg]
