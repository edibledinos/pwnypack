from pwnypack.asm import asm
from pwnypack.shellcode.x86 import X86


__all__ = ['X86NullSafe']


class X86NullSafe(X86):
    @property
    def GETPC1(self):
        return [
            '\tjmp __getpc1',
            '__getpc0:',
            '\tpop %s' % self.OFFSET_REG,
        ]

    GETPC2 = [
        '\tjmp __realstart',
        '__getpc1:',
        '\tcall __getpc0',
        '__realstart:',
    ]

    HALF_REG = {}
    for pair in ((X86.EAX, X86.AX, X86.AL), (X86.EBX, X86.BX, X86.BL),
                 (X86.ECX, X86.CX, X86.CL), (X86.EDX, X86.DX, X86.DL),
                 (X86.ESI, X86.SI), (X86.EDI, X86.DI), (X86.EBP, X86.BP),
                 (X86.ESP, X86.SP)):
        for reg, half in zip(pair, pair[1:]):
            HALF_REG[reg] = half
    del pair, reg, half

    HIGH_REG = {
        X86.AX: X86.AH,
        X86.BX: X86.BH,
        X86.CX: X86.CH,
        X86.DX: X86.DH,
    }

    def reg_add_imm(self, reg, value):
        reg_width = self.REGISTER_WIDTH[reg]
        temp_reg = self.TEMP_REG[reg_width]

        if not value:
            return []
        elif value < 3:
            return ['inc %s' % reg] * value
        elif value < 256 and value not in (10, 13):
            return ['add %s, %d' % (reg, value)]
        elif reg is not temp_reg:
            return self.reg_load_imm(temp_reg, value) + \
               ['add %s, %s' % (reg, temp_reg)]
        else:
            return ['push %s' % reg] + \
               self.reg_load_imm(reg, value) + [
                   'add [%s], %s' % (self.STACK_REG, reg),
                   'pop %s' % reg,
               ]

    def reg_load_imm(self, reg, value):
        orig_reg = reg
        orig_reg_width = reg_width = self.REGISTER_WIDTH[reg]

        if value >= 2 ** reg_width:
            raise ValueError('%d does not fit %s' % (value, reg))

        # 0 value, always use xor
        elif not value:
            return ['xor %s, %s' % (reg, reg)]

        preamble = []

        # reduce size until smallest addressable sub-register
        while reg in self.HALF_REG:
            if value >> (reg_width / 2):
                break

            if not preamble:
                if reg_width <= 32:
                    preamble = ['xor %s, %s' % (reg, reg)]
                else:
                    # xor eax, eax is zero extended and yields a shorter opcode
                    preamble = ['xor %s, %s' % (self.HALF_REG[reg], self.HALF_REG[reg])]

            reg = self.HALF_REG[reg]
            reg_width /= 2

        zero = preamble + (['xor %s, %s' % (reg, reg)] if not preamble else [])

        # Fast path direct load where higher 8 bit of 16 bit register is addressable
        if reg in self.HIGH_REG and value < 0x10000 and not value & 0xff:
            reg = self.HIGH_REG[reg]
            value >>= 8

        if value & 0xff in (0, 10, 13):
            value += 1
            postamble = ['dec %s' % reg]
        else:
            postamble = []

        # Value contains no NUL, \r or \n bytes, load directly
        if reg_width == 8 or not any((value >> i) & 0xff in (0, 10, 13) for i in range(8, reg_width, 8)):
            return preamble + ['mov %s, %d' % (reg, value)] + postamble

        # Fast path direct load of 7 bit in non 8 bit addressable registers
        elif value < 0x80:
            # 32bit register yields smallest opcode
            if orig_reg_width == 64:
                reg = self.HALF_REG[orig_reg]
            elif orig_reg_width == 32:
                reg = orig_reg

            if value == 1:
                return zero + ['inc %s' % reg] + postamble
            else:
                return zero + ['or %s, %d' % (reg, value)] + postamble

        # Use xor to mask NUL bytes
        else:
            value += len(postamble)

            mask = sum([
                (0xff if (value >> i) & 0xff not in (0xf2, 0xf5, 0xff) else 0x7f) << i
                for i in range(0, reg_width, 8)
            ])
            masked_value = value ^ mask

            if reg_width <= 32:
                # Use xor r, imm
                return preamble + [
                    'mov %s, %d' % (reg, mask),
                    'xor %s, %d' % (reg, masked_value),
                ]
            else:
                # No 64bit immediate xor, use stack
                return preamble + [
                    'mov %s, %d' % (reg, mask),
                    'push %s' % reg,
                    'mov %s, %d' % (reg, masked_value),
                    'xor [%s], %s' % (self.STACK_REG, reg),
                    'pop %s' % reg,
                ]

    def reg_load_offset(self, reg, value):
        if value == 0:
            return self.reg_load_reg(reg, self.OFFSET_REG)
        else:
            return self.reg_load_imm(reg, value) + \
                   self.reg_add_reg(reg, self.OFFSET_REG)

    def finalize(self, code, data):
        if data:
            # Determine length of nullify + shellcode and adjust data pointer
            code_len = len(asm('\n'.join(code), target=self.target))
            adjust_ebp = self.reg_add_imm(self.OFFSET_REG, code_len)
            get_pc = self.GETPC1 + ['\t%s' % line for line in adjust_ebp] + self.GETPC2
        else:
            get_pc = []

        # Return finalized code
        return self.PREAMBLE + \
            get_pc + \
            ['\t%s' % line for line in code] + \
            self.finalize_data(data)
