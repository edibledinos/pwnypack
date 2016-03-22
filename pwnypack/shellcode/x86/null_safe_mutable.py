try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict
import six

from pwnypack.shellcode.x86.null_safe import X86NullSafe


__all__ = ['X86NullSafeMutable']


class X86NullSafeMutable(X86NullSafe):
    def finalize(self, code, data):
        xor_offsets = []
        masked_data = OrderedDict()

        offset = 0
        for datum, (_, orig_datum) in six.iteritems(data):
            xor_offsets.extend([
                offset + i
                for i, b in enumerate(six.iterbytes(datum))
                if b in (0, 10, 13)
            ])

            masked_datum = b''.join([
                six.int2byte(b) if b not in (0, 10, 13)
                else six.int2byte(b ^ 0xff)
                for b in six.iterbytes(datum)
            ])
            masked_data[masked_datum] = (offset, orig_datum)

            offset += len(masked_datum)

        if xor_offsets:
            # Build code to restore NUL, \r and \n
            null_code = self.reg_load(self.BL, 255) + \
                        self.reg_load(self.TEMP_PTR, self.OFFSET_REG)
            last_offset = 0
            for offset in xor_offsets:
                offset -= last_offset
                null_code.extend(
                    self.reg_add_imm(self.TEMP_PTR, offset) +
                    ['xor [%s], bl' % self.TEMP_PTR]
                )
                last_offset += offset
        else:
            null_code = []

        return super(X86NullSafeMutable, self).finalize(null_code + code, masked_data)
