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
    endian = kwargs.get('endian', kwargs.get('target', pwnypack.target.target).endian)
    if fmt and fmt[0] not in '@=<>!':
        if endian is pwnypack.target.Endianness.little:
            fmt = '<' + fmt
        elif endian is pwnypack.target.Endianness.big:
            fmt = '>' + fmt
        else:
            raise NotImplementedError('Unsupported endianness: %s' % endian)
    return struct.pack(fmt, *args)


def unpack(fmt, data, **kwargs):
    endian = kwargs.get('endian', kwargs.get('target', pwnypack.target.target).endian)
    if fmt and fmt[0] not in '@=<>!':
        if endian is pwnypack.target.Endianness.little:
            fmt = '<' + fmt
        elif endian is pwnypack.target.Endianness.big:
            fmt = '>' + fmt
        else:
            raise NotImplementedError('Unsupported endianness: %s' % endian)
    return struct.unpack(fmt, data)


def pack_size(fmt, **kwargs):
    endian = kwargs.get('endian', kwargs.get('target', pwnypack.target.target).endian)
    if fmt and fmt[0] not in '@=<>!':
        if endian is pwnypack.target.Endianness.little:
            fmt = '<' + fmt
        elif endian is pwnypack.target.Endianness.big:
            fmt = '>' + fmt
        else:
            raise NotImplementedError('Unsupported endianness: %s' % endian)
    return struct.calcsize(fmt)


def _pack_closure(f, fmt):
    return lambda a, **k: f(fmt, a, **k)


def _unpack_closure(f, fmt):
    return lambda a, **k: f(fmt, a, **k)[0]


for _w, _f in ((8, 'b'), (16, 'h'), (32, 'l'), (64, 'q')):
    locals().update({
        'p%d' % _w: _pack_closure(pack, _f),
        'P%d' % _w: _pack_closure(pack, _f.upper()),
        'u%d' % _w: _unpack_closure(unpack, _f),
        'U%d' % _w: _unpack_closure(unpack, _f.upper()),
    })
    __all__.extend([
        'p%d' % _w,
        'P%d' % _w,
        'u%d' % _w,
        'U%d' % _w,
    ])
del _w, _f, _pack_closure, _unpack_closure


def P(value, **kwargs):
    bits = kwargs.get('bits', kwargs.get('target', pwnypack.target.target).bits)
    return globals()['P%d' % bits](value, **kwargs)


def p(value, **kwargs):
    bits = kwargs.get('bits', kwargs.get('target', pwnypack.target.target).bits)
    return globals()['p%d' % bits](value, **kwargs)


def U(data, **kwargs):
    bits = kwargs.get('bits', kwargs.get('target', pwnypack.target.target).bits)
    return globals()['U%d' % bits](data, **kwargs)


def u(data, **kwargs):
    bits = kwargs.get('bits', kwargs.get('target', pwnypack.target.target).bits)
    return globals()['u%d' % bits](data, **kwargs)
