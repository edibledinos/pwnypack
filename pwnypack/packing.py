import pwnypack.target
import struct


__all__ = [
    'pack',
    'unpack',
    'pack_size',
    'P',
    'p',
    'U',
    'u',
]


def pack(fmt, *args, **kwargs):
    """pack(fmt, v1, v2, ..., endian=None, target=None)

    Return a string containing the values v1, v2, ... packed according to the
    given format. The actual packing is performed by ``struct.pack`` but the
    byte order will be set according to the given `endian`, `target` or
    byte order of the global target.

    Args:
        fmt(str): The format string.
        v1,v2,...: The values to pack.
        endian(:class:`~pwnypack.target.Target.Endian`): Override the default
            byte order. If ``None``, it will look at the byte order of
            the ``target`` argument.
        target(:class:`~pwnypack.target.Target`): Override the default byte
            order. If ``None``, it will look at the byte order of
            the global :data:`~pwnypack.target.target`.

    Returns:
        bytes: The provided values packed according to the format.
    """

    endian, target = kwargs.get('endian'), kwargs.get('target')
    endian = endian if endian is not None else target.endian if target is not None else pwnypack.target.target.endian
    if fmt and fmt[0] not in '@=<>!':
        if endian is pwnypack.target.Target.Endian.little:
            fmt = '<' + fmt
        elif endian is pwnypack.target.Target.Endian.big:
            fmt = '>' + fmt
        else:
            raise NotImplementedError('Unsupported endianness: %s' % endian)
    return struct.pack(fmt, *args)


def unpack(fmt, data, endian=None, target=None):
    """
    Unpack the string (presumably packed by pack(fmt, ...)) according to the
    given format. The actual unpacking is performed by ``struct.unpack``
    but the byte order will be set according to the given `endian`, `target`
    or byte order of the global target.

    Args:
        fmt(str): The format string.
        data(bytes): The data to unpack.
        endian(:class:`~pwnypack.target.Target.Endian`): Override the default
            byte order. If ``None``, it will look at the byte order of
            the ``target`` argument.
        target(:class:`~pwnypack.target.Target`): Override the default byte
            order. If ``None``, it will look at the byte order of
            the global :data:`~pwnypack.target.target`.

    Returns:
        list: The unpacked values according to the format.
    """

    endian = endian if endian is not None else target.endian if target is not None else pwnypack.target.target.endian
    if fmt and fmt[0] not in '@=<>!':
        if endian is pwnypack.target.Target.Endian.little:
            fmt = '<' + fmt
        elif endian is pwnypack.target.Target.Endian.big:
            fmt = '>' + fmt
        else:
            raise NotImplementedError('Unsupported endianness: %s' % endian)
    return struct.unpack(fmt, data)


def pack_size(fmt, endian=None, target=None):
    endian = endian if endian is not None else target.endian if target is not None else pwnypack.target.target.endian
    if fmt and fmt[0] not in '@=<>!':
        if endian is pwnypack.target.Target.Endian.little:
            fmt = '<' + fmt
        elif endian is pwnypack.target.Target.Endian.big:
            fmt = '>' + fmt
        else:
            raise NotImplementedError('Unsupported endianness: %s' % endian)
    return struct.calcsize(fmt)


def _pack_closure(fmt):
    return lambda value, endian=None, target=None: pack(fmt, value, endian=endian, target=target)


def _unpack_closure(fmt):
    return lambda data, endian=None, target=None: unpack(fmt, data, endian=endian, target=target)[0]


for _w, _f in ((8, 'b'), (16, 'h'), (32, 'l'), (64, 'q')):
    locals().update({
        'p%d' % _w: _pack_closure(_f),
        'P%d' % _w: _pack_closure(_f.upper()),
        'u%d' % _w: _unpack_closure(_f),
        'U%d' % _w: _unpack_closure(_f.upper()),
    })

    locals()['p%d' % _w].__doc__ = '''Pack signed %d bit integer. Alias for ``pack('%s', ...)``.''' % (_w, _f)
    locals()['P%d' % _w].__doc__ = '''Pack unsigned %d bit integer. Alias for ``pack('%s', ...)``.''' % (_w, _f.upper())
    locals()['u%d' % _w].__doc__ = '''Unpack signed %d bit integer. Alias for ``unpack('%s', ...)``.''' % (_w, _f)
    locals()['U%d' % _w].__doc__ = '''Unpack unsigned %d bit integer. Alias for ``unpack('%s', ...)``.''' % \
                                   (_w, _f.upper())

    __all__.extend([
        'p%d' % _w,
        'P%d' % _w,
        'u%d' % _w,
        'U%d' % _w,
    ])
del _w, _f, _pack_closure, _unpack_closure


def _get_bits(bits=None, target=None):
    """
    Determine the number of bits to pack/unpack.
    """

    if bits is not None:
        bits = int(bits)
        if bits in (8, 16, 32, 64):
            return bits
        else:
            raise ValueError('bits needs to be 8, 16, 32 or 64')
    else:
        return int((target if target is not None else pwnypack.target.target).bits)


def P(value, bits=None, endian=None, target=None):
    """
    Pack an unsigned pointer for a given target.

    Args:
        value(int): The value to pack.
        bits(:class:`~pwnypack.target.Target.Bits`): Override the default
            word size. If ``None`` it will look at the word size of
            ``target``.
        endian(:class:`~pwnypack.target.Target.Endian`): Override the default
            byte order. If ``None``, it will look at the byte order of
            the ``target`` argument.
        target(:class:`~pwnypack.target.Target`): Override the default byte
            order. If ``None``, it will look at the byte order of
            the global :data:`~pwnypack.target.target`.
    """

    return globals()['P%d' % _get_bits(bits, target)](value, endian=endian, target=target)


def p(value, bits=None, endian=None, target=None):
    """
    Pack a signed pointer for a given target.

    Args:
        value(int): The value to pack.
        bits(:class:`pwnypack.target.Target.Bits`): Override the default
            word size. If ``None`` it will look at the word size of
            ``target``.
        endian(:class:`~pwnypack.target.Target.Endian`): Override the default
            byte order. If ``None``, it will look at the byte order of
            the ``target`` argument.
        target(:class:`~pwnypack.target.Target`): Override the default byte
            order. If ``None``, it will look at the byte order of
            the global :data:`~pwnypack.target.target`.
    """

    return globals()['p%d' % _get_bits(bits, target)](value, endian=endian, target=target)


def U(data, bits=None, endian=None, target=None):
    """
    Unpack an unsigned pointer for a given target.

    Args:
        data(bytes): The data to unpack.
        bits(:class:`pwnypack.target.Target.Bits`): Override the default
            word size. If ``None`` it will look at the word size of
            ``target``.
        endian(:class:`~pwnypack.target.Target.Endian`): Override the default
            byte order. If ``None``, it will look at the byte order of
            the ``target`` argument.
        target(:class:`~pwnypack.target.Target`): Override the default byte
            order. If ``None``, it will look at the byte order of
            the global :data:`~pwnypack.target.target`.

    Returns:
        int: The pointer value.
    """

    return globals()['U%d' % _get_bits(bits, target)](data, endian=endian, target=target)


def u(data, bits=None, endian=None, target=None):
    """
    Unpack a signed pointer for a given target.

    Args:
        data(bytes): The data to unpack.
        bits(:class:`pwnypack.target.Target.Bits`): Override the default
            word size. If ``None`` it will look at the word size of
            ``target``.
        endian(:class:`~pwnypack.target.Target.Endian`): Override the default
            byte order. If ``None``, it will look at the byte order of
            the ``target`` argument.
        target(:class:`~pwnypack.target.Target`): Override the default byte
            order. If ``None``, it will look at the byte order of
            the global :data:`~pwnypack.target.target`.

    Returns:
        int: The pointer value.
    """

    return globals()['u%d' % _get_bits(bits, target)](data, endian=endian, target=target)
