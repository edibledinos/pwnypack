import dpflib.target
import struct


__all__ = [
    'pack',
    'unpack',
    'P',
    'U',
]


def pack(format, *args, **kwargs):
    _target = kwargs.get('target', dpflib.target.target)
    if format and format[0] not in '@=<>!':
        if _target.endian == dpflib.target.Endianness.little:
            format = '<' + format
        elif _target.endian == dpflib.target.Endianness.big:
            format = '>' + format
        else:
            raise NotImplementedError('Unsupported endianness: %s' % _target.endian)
    return struct.pack(format, *args)


def unpack(format, *args, **kwargs):
    global target
    _target = kwargs.get('target', target)
    if format and format[0] not in '@=<>!':
        if _target.endian == dpflib.target.Endianness.little:
            format = '<' + format
        elif _target.endian == dpflib.target.Endianness.big:
            format = '>' + format
        else:
            raise NotImplementedError('Unsupported endianness: %s' % _target.endian)
    return struct.unpack(format, *args)


def _make_closure(f, fmt):
    return lambda *a, **k: f(fmt * len(a), *a, **k)

for _w, _f in ((8, 'b'), (16, 'h'), (32, 'l'), (64, 'q')):
    locals().update({
        'p%d' % _w: _make_closure(pack, _f),
        'P%d' % _w: _make_closure(pack, _f.upper()),
        'u%d' % _w: _make_closure(unpack, _f),
        'U%d' % _w: _make_closure(unpack, _f.upper()),
    })
    __all__.extend([
        'p%d' % _w,
        'P%d' % _w,
        'u%d' % _w,
        'U%d' % _w,
    ])
del _w, _f, _make_closure


def P(*args, **kwargs):
    bits = kwargs.get('target', dpflib.target.target).bits
    return globals()['P%d' % bits](*args, **kwargs)


def U(*args, **kwargs):
    bits = kwargs.get('target', dpflib.target.target).bits
    return globals()['P%d' % bits](*args, **kwargs)
