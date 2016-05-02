try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

import six

from pwnypack.asm import asm


def _pack_data(data):
    return ['__data:'] + [
        '\tdb ' + ','.join(hex(b) for b in six.iterbytes(datum)) + '  ; ' + repr(orig_datum)
        for datum, (_, orig_datum) in six.iteritems(data)
    ]


def nasm_mutable_data_finalizer(env, code, data):
    """
    Simple data allocation strategy that expects the code to be in a writable
    segment. We just append the data to the end of the code.
    """

    if env.target.bits == 32:
        get_pc = [
            '\tcall __getpc0',
            '__getpc0:',
            '\tpop %s' % env.OFFSET_REG,
            '\tadd %s, __data - __getpc0' % env.OFFSET_REG,
            '__realstart:',
        ]
    else:
        get_pc = ['\tlea %s, [rel __data]' % env.OFFSET_REG]

    if data or env.buffers:
        return get_pc + code + _pack_data(data)
    else:
        return code


def nasm_null_safe_mutable_data_finalizer(env, code, data):
    """
    Simple data allocation strategy that expects the code to be in a writable
    segment. We just append the data to the end of the code.
    """

    if data or env.buffers:
        # Determine length of nullify + shellcode and adjust data pointer
        xor_offsets = []
        masked_data = OrderedDict()

        for datum, (offset, orig_datum) in six.iteritems(data):
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

        if xor_offsets:
            # Build code to restore NUL, \r and \n
            temp_reg = env.TEMP_REG[env.target.bits]
            null_code = env.reg_load(env.BL, 255) + \
                        env.reg_load(temp_reg, env.OFFSET_REG)

            last_offset = 0
            for offset in xor_offsets:
                offset -= last_offset
                null_code.extend(
                    env.reg_add(temp_reg, offset) +
                    ['xor [%s], bl' % temp_reg]
                )
                last_offset += offset
            code = ['\t%s' % line for line in null_code] + code
            data = masked_data

        code_len = len(asm('\n'.join(code), target=env.target))
        adjust_ebp = env.reg_add(env.OFFSET_REG, code_len)

        return [
            '\tjmp __getpc1',
            '__getpc0:',
            '\tpop %s' % env.OFFSET_REG,
        ] + [
            '\t%s' % line for line in adjust_ebp
        ] + [
            '\tjmp __realstart',
            '__getpc1:',
            '\tcall __getpc0',
            '__realstart:',
        ] + code + _pack_data(data)
    else:
        return code
