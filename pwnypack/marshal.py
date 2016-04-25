"""
This module contains functions to load and unserialize data (including .pyc
files) serialized using the :mod:`marshal` module on most version of python.
"""

import datetime
from enum import IntEnum

import six

from pwnypack.bytecode import CodeObject
from pwnypack.py_internals import PY_INTERNALS, get_py_internals
from pwnypack.packing import U16, u16, U32, u32, u64, unpack
from pwnypack.target import Target


__all__ = ['marshal_load', 'marshal_loads', 'pyc_load', 'pyc_loads']


MAGIC_MAP = dict(
    (internals['magic'], internals)
    for version, internals in six.iteritems(PY_INTERNALS)
    if version is not None
)
MARSHAL_TARGET = Target(Target.Arch.unknown, Target.Bits.bits_32, Target.Endian.little)
NULL = object()
PyLong_MARSHAL_SHIFT = 15
FLAG_REF = 0x80


class ObjectType(IntEnum):
    """
    Enumeration used internally to describe / parse a marshal object type.
    """

    null = ord('0')
    none = ord('N')
    false = ord('F')
    true = ord('T')
    stopiter = ord('S')
    ellipsis = ord('.')
    int = ord('i')
    int64 = ord('I')
    float = ord('f')
    binary_float = ord('g')
    complex = ord('x')
    binary_complex = ord('y')
    long = ord('l')
    string = ord('s')
    stringref = ord('R')
    interned = ord('t')
    ref = ord('r')
    tuple = ord('(')
    list = ord('[')
    dict = ord('{')
    code = ord('c')
    unicode = ord('u')
    unknown = ord('?')
    set = ord('<')
    frozenset = ord('>')
    ascii = ord('a')
    ascii_interned = ord('A')
    small_tuple = ord(')')
    short_ascii = ord('z')
    short_ascii_interned = ord('Z')


def marshal_load(fp, origin=None):
    """
    Unserialize data serialized with :func:`marshal.dump`. This function
    works across python versions. Marshalled code objects are returned as
    instances of :class:`~pwnypack.bytecode.CodeObject`.

    Arguments:
        fp(file): A file or file-like object that contains the serialized
            data.
        origin(dict): The opcode specification of the python version that
            generated the data. If you provide ``None``, the specs for the
            currently running python version will be used.

    Returns:
        The unserialized data.
    """

    origin = get_py_internals(origin)
    version = origin['version']

    refs = []

    def ref(o, flags):
        if flags & FLAG_REF:
            refs.append(o)
        return o

    def read_byte():
        return six.byte2int(fp.read(1))

    def read_short():
        return u16(fp.read(2), target=MARSHAL_TARGET)

    def read_long():
        return u32(fp.read(4), target=MARSHAL_TARGET)

    def read_int64():
        return u64(fp.read(8), target=MARSHAL_TARGET)

    def read_float_binary():
        return unpack('d', fp.read(8), target=MARSHAL_TARGET)[0]

    def read_bytes():
        return fp.read(read_long())

    def read_bytes_short():
        return fp.read(read_byte())

    def read_float_text():
        return float(read_bytes_short())

    def read_object():
        c = six.byte2int(fp.read(1))
        flags = c & FLAG_REF
        c = ObjectType(c & ~FLAG_REF)

        if c is ObjectType.null:
            return NULL
        elif c is ObjectType.none:
            return None
        elif c is ObjectType.stopiter:
            return StopIteration
        elif c is ObjectType.ellipsis:
            return Ellipsis
        elif c is ObjectType.false:
            return False
        elif c is ObjectType.true:
            return True
        elif c is ObjectType.int:
            return ref(read_long(), flags)
        elif c is ObjectType.int64:
            return ref(read_int64(), flags)
        elif c is ObjectType.long:
            n = read_long()
            r = sum(
                read_short() << (i * PyLong_MARSHAL_SHIFT)
                for i in range(abs(n))
            )
            return ref(-r if n < 0 else r, flags)
        elif c is ObjectType.float:
            return ref(read_float_text(), flags)
        elif c is ObjectType.binary_float:
            return ref(read_float_binary(), flags)
        elif c is ObjectType.complex:
            real = read_float_text()
            imag = read_float_text()
            return ref(complex(real, imag), flags)
        elif c is ObjectType.binary_complex:
            real = read_float_binary()
            imag = read_float_binary()
            return ref(complex(real, imag), flags)
        elif c is ObjectType.string:
            return ref(read_bytes(), flags)
        elif c is ObjectType.unicode:
            return ref(read_bytes().decode('utf-8'), flags)
        elif c is ObjectType.interned:
            if version < 30:
                return ref(read_bytes(), FLAG_REF)
            else:
                return ref(read_bytes().decode('utf-8'), flags)
        elif c is ObjectType.ascii:
            return ref(read_bytes().decode('ascii'), flags)
        elif c is ObjectType.ascii_interned:
            return ref(read_bytes().decode('ascii'), flags)
        elif c is ObjectType.short_ascii:
            return ref(read_bytes_short().decode('ascii'), flags)
        elif c is ObjectType.short_ascii_interned:
            return ref(read_bytes_short().decode('ascii'), flags)
        elif c in (ObjectType.tuple, ObjectType.small_tuple, ObjectType.frozenset):
            ref_index = len(refs)
            ref(NULL, flags)
            r_type = frozenset if c is ObjectType.frozenset else tuple
            n = read_byte() if c is ObjectType.small_tuple else read_long()
            r = r_type(read_object() for _ in range(n))
            if flags & FLAG_REF:
                refs[ref_index] = r
            return r
        elif c is ObjectType.list:
            r = ref([], flags)
            for _ in range(read_long()):
                r.append(read_object())
            return r
        elif c is ObjectType.set:
            r = ref(set(), flags)
            for _ in range(read_long()):
                r.add(read_object())
            return r
        elif c is ObjectType.dict:
            r = ref({}, flags)
            while True:
                k = read_object()
                if k is NULL:
                    break
                r[k] = read_object()
            return r
        elif c in (ObjectType.stringref, ObjectType.ref):
            return refs[read_long()]
        elif c is ObjectType.code:
            ref_index = len(refs)
            ref(NULL, flags)

            co_argcount = read_long()
            if version < 30:
                co_kwonlyargcount = 0
            else:
                co_kwonlyargcount = read_long()
            co_nlocals = read_long()
            co_stacksize = read_long()
            co_flags = read_long()
            co_code = read_object()
            co_consts = read_object()
            co_names = read_object()
            co_varnames = read_object()
            co_freevars = read_object()
            co_cellvars = read_object()
            co_filename = read_object()
            co_name = read_object()
            co_firstlineno = read_long()
            co_lnotab = read_object()

            r = CodeObject(
                co_argcount,
                co_kwonlyargcount,
                co_nlocals,
                co_stacksize,
                co_flags,
                co_code,
                co_consts,
                co_names,
                co_varnames,
                co_filename,
                co_name,
                co_firstlineno,
                co_lnotab,
                co_freevars,
                co_cellvars,
                origin,
            )
            if flags & FLAG_REF:
                refs[ref_index] = r
            return r
        else:
            raise ValueError('Unexpected object type %s.' % c)

    return read_object()


def marshal_loads(data, origin=None):
    """
    Load data serialized with :func:`marshal.dump` from a bytestring.

    Arguments:
        data(bytes): The marshalled data.
        origin(dict): The opcode specification of the python version that
            generated the data. If you provide ``None``, the specs for the
            currently running python version will be used.

    Returns:
        The unserialized data.
    """

    return marshal_load(six.BytesIO(data), origin)


class PycFile(object):
    """
    This class describes a parsed .pyc file and is returned by
    :func:`pyc_load` and :func:`pyc_loads`.
    """

    def __init__(self, magic, origin, timestamp, file_size, code):
        self.magic = magic  #: The magic number of the python version that created the file.
        self.origin = origin  #: The internals of the accompanying python version.
        self.timestamp = timestamp  #: The timestamp of the original source file.
        self.file_size = file_size  #: The original source file's since (or None if version < 3.3).
        self.code = code  #: The :class:`CodeObject` instance that represents the contents of the .pyc file.


def pyc_load(fp):
    """
    Load a .pyc file from a file-like object.

    Arguments:
        fp(file): The file-like object to read.

    Returns:
        PycFile: The parsed representation of the .pyc file.
    """

    magic_1 = U16(fp.read(2), target=MARSHAL_TARGET)
    magic_2 = U16(fp.read(2), target=MARSHAL_TARGET)

    internals = MAGIC_MAP.get(magic_1)
    if internals is None:
        raise ValueError('Invalid or unknown magic (%d).' % magic_1)

    if magic_2 != 2573:
        raise ValueError('Invalid secondary magic (%d).' % magic_2)

    timestamp = datetime.datetime.fromtimestamp(U32(fp.read(4), target=MARSHAL_TARGET))

    if internals['version'] >= 33:
        file_size = U32(fp.read(4))
    else:
        file_size = None

    code_object = marshal_load(fp, internals)

    return PycFile(magic_1, internals, timestamp, file_size, code_object)


def pyc_loads(data):
    """
    Load a .pyc file from a bytestring.

    Arguments:
        data(bytes): The content of the .pyc file.

    Returns:
        PycFile: The parsed representation of the .pyc file.
    """

    return pyc_load(six.BytesIO(data))
