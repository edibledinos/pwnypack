"""
The :class:`Target` class describes the architecture of a targeted machine,
executable or environment. It encodes the generic architecture, the word
size, the byte order and an architecture dependant mode.

It is used throughout *pwnypack* to determine how data should be interpreted
or emitted.
"""


import platform
from enum import IntEnum, Enum
import sys


__all__ = [
    'Target',
    'target',
]


class Target(object):
    class Arch(Enum):
        """
        Describes the general architecture of a target.
        """

        x86 = 'x86'          #: X86 architecture.
        arm = 'arm'          #: ARM architecture.
        unknown = 'unknown'  #: Any other architecture.

    class Bits(IntEnum):
        """
        The target architecture's word size.
        """

        bits_32 = 32  #: 32 bit word size.
        bits_64 = 64  #: 64 bit word size.

    class Endian(IntEnum):
        """
        The target architecture's byte order.
        """

        little = 0  #: Little endian.
        big = 1     #: Big endian.

    class Mode(IntEnum):
        """
        Architecture dependant mode flags.
        """

        arm_v8 = 1 << 0       #: Use ARM V8 instruction set
        arm_thumb = 1 << 1    #: Use ARM Thumb instruction set
        arm_m_class = 1 << 2  #: Use ARMv7-M instruction set

    _DEFAULT_ARCH = {
        'i386': Arch.x86,
        'x86_64': Arch.x86,
    }

    _VALID_BITS = {}

    _DEFAULT_BITS = {
        Arch.x86: Bits.bits_32,
        Arch.arm: Bits.bits_32,
    }

    _VALID_ENDIAN = {
        Arch.x86: [Endian.little],
    }

    _DEFAULT_ENDIAN = {
        Arch.x86: Endian.little,
        Arch.arm: Endian.little,
    }

    _arch = None
    _bits = None
    _endian = None
    _mode = None

    def __init__(self, arch=None, bits=None, endian=None, mode=0):
        if arch is None:
            arch = self._DEFAULT_ARCH.get(platform.machine(), Target.Arch.unknown)

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
        """
        The target's architecture. One of :class:`Target.Arch`.
        """
        return self._arch

    @arch.setter
    def arch(self, arch):
        if arch is None:
            arch = Target.Arch.unknown
        self._arch = Target.Arch(arch)

    @property
    def bits(self):
        """
        The target architecture word size. One of :class:`Target.Bits`.
        """
        if self._bits is None:
            value = self._DEFAULT_BITS.get(self.arch)
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
            assert self._bits in self._VALID_BITS.get(
                self.arch,
                [Target.Bits.bits_32, Target.Bits.bits_64]
            ), '%s not supported on %s' % (self._bits, self._arch)

    @property
    def endian(self):
        """
        The target architecture byte order. One of :class:`Target.Endian`.
        """
        if self._endian is None:
            value = self._DEFAULT_ENDIAN[self.arch]
            if value is None:
                raise NotImplementedError('Could not determine the default byte order of %s architecture.' % self.arch)
            return value
        else:
            return self._endian

    @endian.setter
    def endian(self, endian):
        if endian is None:
            self._endian = None
        else:
            self._endian = Target.Endian(endian)
            assert self._endian in self._VALID_ENDIAN.get(
                self.arch,
                [Target.Endian.little, Target.Endian.big]
            ), '%s not supported on %s' % (self._endian, self._arch)

    @property
    def mode(self):
        """
        The target architecture dependant flags. OR'ed values of :class:`Target.Mode`.
        """
        return self._mode

    @mode.setter
    def mode(self, value):
        self._mode = int(value)

    def assume(self, other):
        """
        Assume the identity of another target. This can be useful to make the
        global target assume the identity of an ELF executable.

        Arguments:
            other(:class:`Target`): The target whose identity to assume.

        Example:
            >>> from pwny import *
            >>> target.assume(ELF('my-executable'))
        """

        self._arch = other._arch
        self._bits = other._bits
        self._endian = other._endian
        self._mode = other._mode

    def __repr__(self):
        return '%s(arch=%s,bits=%s,endian=%s,mode=%s)' % (
            self.__class__.__name__,
            self.arch.name,
            self.bits.value,
            self.endian.name,
            self.mode
        )


target = Target()
"""
The global, default target. If no targeting information is provided to a
function, this is the target that will be used.
"""
