import six


def gnu_as_mutable_data_finalizer(get_pc, comment_char, align=True):
    def data_finalizer(env, code, data):
        return (get_pc(env, code) if data or env.buffers else []) + code + [
            '',
            '.pool',
        ] + ([
            '.align',
        ] if align else []) + [
            '__data:',
        ] + [
            '\t.byte %s  %s %r' % (
                ', '.join(hex(b) for b in six.iterbytes(datum)),
                comment_char,
                orig_datum,
            )
            for datum, (_, orig_datum) in six.iteritems(data)
        ]
    return data_finalizer
