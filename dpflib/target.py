from enum import Enum
import platform


__all__ = [
    'Architecture',
    'Endianness',
    'Target',
    'target',
]


class Architecture(Enum):
    x86 = 1
    x86_64 = 2
        

class Endianness(Enum):
    little = 1
    big = 2


class Target(object):
    _arch = None
    _endian = None
    _bits = None

    def __init__(self, arch=None, endian=None, bits=None):
        self.arch = arch
        self.endian = endian
        self.bits = bits

    @property
    def arch(self):
        if self._arch is None:
            if platform.architecture()[0] == '64bit':
                return Architecture.x86_64
            else:
                return Architecture.x86
        return self._arch

    @arch.setter
    def arch(self, arch):
        self._arch = arch

    @property
    def endian(self):
        if self._endian is None:
            # Both x86 and x86_64 use little endian.
            return Endianness.little
        else:
            return self._endian

    @endian.setter
    def endian(self, endian):
        self._endian = endian

    @property
    def bits(self):
        if self._bits is None:
            arch = self.arch
            if arch is Architecture.x86:
                return 32
            elif arch is Architecture.x86_64:
                return 64
            else:
                raise NotImplementedError('Unsupported architecture: %s' % arch)
        else:
            return self._bits

    @bits.setter
    def bits(self, value):
        self._bits = value


target = Target()
