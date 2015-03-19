from dpflib.target import Architecture, Endianness, Target
from dpflib.packing import U16, U32, unpack, packsize
from enum import Enum


__all__ = [
    'ELF',
]


class ELF(Target):
    MAGIC = '\x7fELF'

    class Type(Enum):
        none = 0
        relocatable = 1
        executable = 2
        shared = 3
        core = 4

    class OSABI(Enum):
        system_v = 0x00
        hp_ux = 0x01
        netbsd = 0x02
        linux = 0x03
        solaris = 0x06
        aix = 0x07
        irix = 0x08
        freebsd = 0x09
        openbsd = 0x0c
        openvms = 0x0d

    osabi = None
    abi_version = None
    type = None
    entry = None
    phoff = None
    shoff = None
    flags = None
    hsize = None
    phentsize = None
    phnum = None
    shentsize = None
    shnum = None
    shstrndx = None

    def __init__(self):
        pass

    @classmethod
    def parse(cls, f):
        if type(f) is str:
            f = open(f, 'rb')
            need_close = True
        else:
            need_close = False

        elf = cls()

        header = f.read(0x18)
        assert len(header) == 0x18, 'File prematurely ended'
        assert header[:4] == cls.MAGIC, 'Missing ELF magic'

        assert header[4] in '\x01\x02', 'Invalid word size'
        elf.bits = 32 * ord(header[4])
        elf.endian = Endianness(ord(header[5]))
        assert header[6] == chr(1)
        elf.osabi = cls.OSABI(ord(header[7]))
        elf.abi_version = ord(header[8])

        elf.type = cls.Type(U16(header[16:18], endian=elf.endian))
        elf.arch = Architecture(U16(header[18:20], endian=elf.endian))
        assert U32(header[20:24], endian=elf.endian) == 1

        if elf.bits == 32:
            format = 'IIIIHHHHHH'
        elif elf.bits == 64:
            format = 'QQQIHHHHHH'

        header_len = packsize(format)
        header = f.read(header_len)
        assert len(header) == header_len, 'File prematurely ended'

        elf.entry, elf.phoff, elf.shoff, elf.flags, elf.hsize, elf.phentsize, \
            elf.phnum, elf.shentsize, elf.shnum, elf.shstrndx = \
            unpack(format, header, target=elf)

        if need_close:
            f.close()

        return elf
