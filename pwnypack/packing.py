import pwnypack.target
import struct


__all__ = [
    'pack',
    'unpack',
    'P',
    'U',
    'packsize',
]


def pack(format, *args, **kwargs):
    endian = kwargs.get('endian', kwargs.get('target', pwnypack.target.target).endian)
    if format and format[0] not in '@=<>!':
        if endian is pwnypack.target.Endianness.little:
            format = '<' + format
        elif endian is pwnypack.target.Endianness.big:
            format = '>' + format
        else:
            raise NotImplementedError('Unsupported endianness: %s' % endian)
    return struct.pack(format, *args)


def unpack(format, data, **kwargs):
    endian = kwargs.get('endian', kwargs.get('target', pwnypack.target.target).endian)
    if format and format[0] not in '@=<>!':
        if endian is pwnypack.target.Endianness.little:
            format = '<' + format
        elif endian is pwnypack.target.Endianness.big:
            format = '>' + format
        else:
            raise NotImplementedError('Unsupported endianness: %s' % endian)
    return struct.unpack(format, data)


def _pack_closure(f, fmt):
    return lambda *a, **k: f(fmt * len(a), *a, **k)

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


def P(*args, **kwargs):
    bits = kwargs.get('bits', kwargs.get('target', pwnypack.target.target).bits)
    return globals()['P%d' % bits](*args, **kwargs)


def U(data, **kwargs):
    bits = kwargs.get('bits', kwargs.get('target', pwnypack.target.target).bits)
    return globals()['U%d' % bits](data, **kwargs)


def packsize(format, **kwargs):
    endian = kwargs.get('endian', kwargs.get('target', pwnypack.target.target).endian)
    if format and format[0] not in '@=<>!':
        if endian is pwnypack.target.Endianness.little:
            format = '<' + format
        elif endian is pwnypack.target.Endianness.big:
            format = '>' + format
        else:
            raise NotImplementedError('Unsupported endianness: %s' % endian)
    return struct.calcsize(format)
