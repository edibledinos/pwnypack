import platform
from enum import IntEnum, Enum
import struct
import sys


__all__ = [
    'Target',
    'target',
]


class Target(object):
    class Arch(Enum):
        x86 = 'x86'
        arm = 'arm'
        unknown = 'unknown'

    class Bits(IntEnum):
        bits_32 = 32
        bits_64 = 64

    class Endian(IntEnum):
        little = 0
        big = 1

    class Mode(IntEnum):
        arm_v8 = 1 << 0
        arm_thumb = 1 << 1
        arm_class = 1 << 2

    DEFAULT_ARCH = {
        'i386': Arch.x86,
        'x86_64': Arch.x86,
    }

    VALID_BITS = {}

    DEFAULT_BITS = {
        Arch.x86: Bits.bits_32,
        Arch.arm: Bits.bits_32,
    }

    VALID_ENDIAN = {
        Arch.x86: [Endian.little],
    }

    DEFAULT_ENDIAN = {
        Arch.x86: Endian.little,
        Arch.arm: Endian.little,
    }

    _arch = None
    _bits = None
    _endian = None
    _mode = None

    def __init__(self, arch=None, bits=None, endian=None, mode=0):
        if arch is None:
            arch = self.DEFAULT_ARCH.get(platform.machine(), Target.Arch.unknown)

            if bits is None:
                bits = Target.Bits(64 if platform.architecture()[0] == '64bit' else 32)

            if endian is None:
                endian = Target.Endian.__members__[sys.byteorder]

        self.arch = arch
        self.bits = bits
        self.endian = endian
        self.mode = mode

    @property
    def arch(self):
        return self._arch

    @arch.setter
    def arch(self, arch):
        if arch is None:
            arch = Target.Arch.unknown
        self._arch = Target.Arch(arch)

    @property
    def bits(self):
        if self._bits is None:
            value = self.DEFAULT_BITS.get(self.arch)
            if value is None:
                raise NotImplementedError('Could not determine the default word size of %s architecture.' % self.arch)
            return value
        else:
            return self._bits

    @bits.setter
    def bits(self, value):
        if value is None:
            self._bits = None
        else:
            self._bits = Target.Bits(value)
            assert self._bits in self.VALID_BITS.get(
                self.arch,
                [Target.Bits.bits_32, Target.Bits.bits_64]
            ), '%s not supported on %s' % (self._bits, self._arch)

    @property
    def endian(self):
        if self._endian is None:
            value = self.DEFAULT_ENDIAN[self.arch]
            if value is None:
                raise NotImplementedError('Could not determine the default endianness of %s architecture.' % self.arch)
            return value
        else:
            return self._endian

    @endian.setter
    def endian(self, endian):
        if endian is None:
            self._endian = None
        else:
            self._endian = Target.Endian(endian)
            assert self._endian in self.VALID_ENDIAN.get(
                self.arch,
                [Target.Endian.little, Target.Endian.big]
            ), '%s not supported on %s' % (self._endian, self._arch)

    @property
    def mode(self):
        return self._mode

    @mode.setter
    def mode(self, value):
        self._mode = int(value)

    def assume(self, other):
        self._arch = other._arch
        self._bits = other._bits
        self._endian = other._endian
        self._mode = other._mode


target = Target()
