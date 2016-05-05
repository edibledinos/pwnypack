import six

from pwnypack.shellcode.ops import SyscallInvoke


__all__ = ['Register', 'Offset', 'Buffer', 'Array', 'NUMERIC', 'PTR', 'CHARP', 'CHARPP', 'SyscallDef']


class Register(object):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<Reg:%s>' % self.name.upper()


class Offset(int):
    def __repr__(self):
        return 'Offset(%d)' % self


class Buffer(object):
    def __init__(self, offset, length):
        self.offset = offset
        self.length = length

    def __repr__(self):
        return 'Buffer(%d@%d)' % (self.length, self.offset)


class Array(object):
    def __init__(self, item_type):
        self.item_type = item_type

    def verify(self, value):
        if value is not None:
            for item in value:
                self.item_type.verify(item)


class NUMERIC(object):
    @staticmethod
    def verify(value):
        if not isinstance(value, (six.integer_types, Register, SyscallInvoke)):
            raise ValueError('syscall argument not of expected type int')


class PTR(object):
    @staticmethod
    def verify(value):
        if not isinstance(value, (type(None), six.integer_types, Register, Offset, Buffer, SyscallInvoke,
                                  six.string_types, six.binary_type, list)):
            raise ValueError('syscall argument not of expected type ptr')


class CHARP(object):
    @staticmethod
    def verify(value):
        if not isinstance(value, (type(None), six.string_types, six.binary_type, Register, Offset, Buffer)):
            raise ValueError('syscall argument not of expected type str/bytes')


CHARPP = Array(CHARP)


class SyscallDef(object):
    def __init__(self, name, *arg_types):
        self.name = name
        self.arg_types = arg_types

    def __call__(self, *args):
        if not len(args) == len(self.arg_types):
            raise ValueError('Incorrect number of syscall arguments')

        for arg_type, arg_value in zip(self.arg_types, args):
            arg_type.verify(arg_value)

        return SyscallInvoke(self, args)

    def __repr__(self):
        if self.arg_types:
            def translate_arg_type(t):
                if t is NUMERIC:
                    return 'int'
                elif t is PTR:
                    return 'void *'
                elif t is CHARP:
                    return 'void **'
                elif isinstance(t, Array):
                    return '%s[]' % translate_arg_type(t.item_type)
                else:
                    return repr(t)

            return 'SyscallDef(%s: %s)' % (self.name, ', '.join(translate_arg_type(a) for a in self.arg_types))
        else:
            return 'SyscallDef(%s)' % self.name
