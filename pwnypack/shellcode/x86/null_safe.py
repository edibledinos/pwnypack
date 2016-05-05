from pwnypack.codec import find_xor_mask
from pwnypack.packing import P, U
from pwnypack.shellcode.x86 import X86


__all__ = ['X86NullSafe']


class X86NullSafe(X86):
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

    def _reg_add_sub_imm(self, insn, insn_1, reg, value):
        reg_width = self.REGISTER_WIDTH[reg]
        temp_reg = self.TEMP_REG[reg_width]

        if not value:
            return []
        elif value < 3:
            return ['%s %s' % (insn_1, reg)] * value
        elif value in (10, 13):
            return ['%s %s, %d' % (insn, reg, value - 1),
                    '%s %s' % (insn_1, reg)]
        elif value < 128 and value not in (10, 13):
            return ['%s %s, %d' % (insn, reg, value)]
        elif reg is not temp_reg:
            return self.reg_load_imm(temp_reg, value) + \
                   ['%s %s, %s' % (insn, reg, temp_reg)]
        else:
            return ['push %s' % reg] + \
                   self.reg_load_imm(reg, value) + [
                       '%s [%s], %s' % (insn, self.STACK_REG, reg),
                       'pop %s' % reg,
                   ]

    def reg_add_imm(self, reg, value):
        return self._reg_add_sub_imm('add', 'inc', reg, value)

    def reg_sub_imm(self, reg, value):
        return self._reg_add_sub_imm('sub', 'dec', reg, value)

    def reg_add_reg(self, reg1, reg2):
        return ['add %s, %s' % (reg1, reg2)]

    def reg_sub_reg(self, reg1, reg2):
        return ['sub %s, %s' % (reg1, reg2)]

    def reg_load_imm(self, reg, value):
        orig_reg = reg
        orig_reg_width = reg_width = self.REGISTER_WIDTH[reg]

        value &= 2 ** reg_width - 1

        # 0 value, always use xor
        if not value:
            return ['xor %s, %s' % (reg, reg)]

        preamble = []

        # reduce size until smallest addressable sub-register
        while reg in self.HALF_REG and value < 2 ** (reg_width // 2):
            if not preamble:
                if reg_width <= 32:
                    preamble = ['xor %s, %s' % (reg, reg)]
                else:
                    # xor eax, eax is zero extended and yields a shorter opcode
                    preamble = ['xor %s, %s' % (self.HALF_REG[reg], self.HALF_REG[reg])]

            reg = self.HALF_REG[reg]
            reg_width //= 2

        zero = preamble + (['xor %s, %s' % (reg, reg)] if not preamble else [])

        # Fast path direct load where higher 8 bit of 16 bit register is addressable
        if reg in self.HIGH_REG and value < 0x10000 and not value & 0xff:
            reg = self.HIGH_REG[reg]
            reg_width //= 2
            value >>= 8

        # Find a xor solution to compose this value without \0, \r or \n
        xor_solution = [
            U(s, bits=reg_width)
            for s in find_xor_mask(P(value, bits=reg_width))
        ]

        # Find a solution for when value < 256 and is \0, \r or \n.
        if value & 0xff in (0, 10, 13):
            value += 1
            postamble = ['dec %s' % reg]
        else:
            postamble = []

        # Value contains no NUL, \r or \n bytes, load directly
        if reg_width == 8 or len(xor_solution) == 1:
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
            result = preamble

            if reg_width <= 32:
                # Use xor r, imm. Not suitable for 64bit, xor reg, imm64 does not exist
                result.append('mov %s, %d' % (reg, xor_solution[0]))
                for xor_value in xor_solution[1:]:
                    result.append('xor %s, %d' % (reg, xor_value))

            elif reg is not self.TEMP_REG[reg_width]:
                # Use the temporary register to compose our solution
                temp_reg = self.TEMP_REG[reg_width]
                result.append('mov %s, %d' % (reg, xor_solution[0]))
                for xor_value in xor_solution[1:]:
                    result.extend([
                        'mov %s, %d' % (temp_reg, xor_value),
                        'xor %s, %s' % (reg, temp_reg),
                    ])

            else:
                # We're loading the temporary register, use the stack
                result.extend([
                    'mov %s, %d' % (reg, xor_solution[0]),
                    'push %s' % reg,
                ])
                for xor_value in xor_solution[1:]:
                    result.extend([
                        'mov %s, %d' % (reg, xor_value),
                        'xor [%s], %s' % (self.STACK_REG, reg),
                    ])
                result.append('pop %s' % reg)
            return result

    def reg_load_offset(self, reg, value):
        return self.reg_load(reg, int(value)) + \
               ['add %s, %s' % (reg, self.OFFSET_REG)]
