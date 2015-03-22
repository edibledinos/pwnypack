from pwnypack.target import Architecture, Endianness, Target
from pwnypack.packing import U16, U32, unpack, pack_size
from enum import Enum


__all__ = [
    'ELF',
]


class ELF(Target):
    MAGIC = b'\x7fELF'

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

    class SectionType(Enum):
        UNKNOWN = -1
        NULL = 0
        PROGBITS = 1
        SYMTAB = 2
        STRTAB = 3
        RELA = 4
        HASH = 5
        DYNAMIC = 6
        NOTE = 7
        NOBITS = 8
        REL = 9
        DYNSYM = 11
        INIT_ARRAY = 14
        FINI_ARRAY = 15
        PREINIT_ARRAY = 16
        GROUP = 17
        SYMTAB_SHNDX = 18
        NUM = 19
        GNU_ATTRIBUTES = 0x6ffffff5
        GNU_HASH = 0x6ffffff6
        GNU_LIBLIST = 0x6ffffff7
        CHECKSUM = 0x6ffffff8
        LOSUNW = 0x6ffffffa
        SUNW_move = 0x6ffffffa
        SUNW_COMDAT = 0x6ffffffb
        SUNW_syminfo = 0x6ffffffc
        GNU_VERDEF = 0x6ffffffd
        GNU_VERNEED = 0x6ffffffe
        GNU_VERSYM = 0x6fffffff
        HISUNW = 0x6fffffff
        HIOS = 0x6fffffff

    # Flags for section headers.
    SHF_WRITE = 1 << 0
    SHF_ALLOC = 1 < 1
    SHF_EXECINSTR = 1 << 2
    SHF_MERGE = 1 << 4
    SHF_STRINGS = 1 << 5
    SHF_INFO_LINK = 1 << 6
    SHF_LINK_ORDER = 1 << 7
    SHF_OS_NONCONFORMING = 1 << 8
    SHF_GROUP = 1 << 9
    SHF_TLS = 1 << 10
    SHF_MASKOS = 0x0ff00000
    SHF_MASKPROC = 0xf0000000
    SHF_ORDERED = 1 << 30
    SHF_EXCLUDE = 1 << 31

    class SymbolBinding(Enum):
        LOCAL = 0
        GLOBAL = 1
        WEAK = 2
        LOOS = 10
        HIOS = 11
        LOPROC = 13
        HIPROC = 15

    class SymbolType(Enum):
        NOTYPE = 0
        OBJECT = 1
        FUNC = 2
        SECTION = 3
        FILE = 4
        COMMON = 5
        TLS = 6
        LOOS = 10
        HIOS = 12
        LOPROC = 13
        HIPROC = 15

    class SymbolVisibility(Enum):
        DEFAULT = 0
        INTERNAL = 1
        HIDDEN = 2
        PROTECTED = 3

    # Special section indexes
    SHN_UNDEF = 0
    SHN_ABS = 0xfff1
    SHN_COMMON = 0xfff2

    def __init__(self, f=None):
        super(ELF, self).__init__()
        self.osabi = self.abi_version = self.type = self.entry = self.phoff = \
            self.shoff = self.flags = self.hsize = self.phentsize = self.phnum = \
            self.shentsize = self.shnum = self.shstrndx = \
            self.strings = self.raw_section_strings = None

        self.sections_by_name = {}
        self.sections_by_index = []

        self.f = None

        if f is not None:
            self.parse_file(f)

    def parse_file(self, f):
        if type(f) is str:
            self.f = open(f, 'rb')
        else:
            self.f = f

        self.parse_header(self.f.read(64))

        if self.shnum:
            strings = self.read_section(self.load_section_header(self.shstrndx))
            self.strings = {}  # Will be filled by parsing sections.
            self.raw_section_strings = strings.decode('ascii')

            self.f.seek(self.shoff)
            for i in range(self.shnum):
                section = self.parse_section_header(self.f.read(self.shentsize))
                self.sections_by_name[section['name']] = section
                self.sections_by_index.append(section)

    def parse_header(self, data):
        (magic, bits, endian, version, osabi, abi_version, _), data = \
            unpack('4sBBBBB7s', data[:16]), data[16:]

        assert magic == self.MAGIC, 'Missing ELF magic'

        assert bits in (1, 2), 'Invalid word size'
        self.bits = 32 * bits

        self.endian = Endianness(endian)

        assert version == 1, 'Invalid version'

        self.osabi = self.OSABI(osabi)
        self.abi_version = abi_version

        (type_, arch, version), data = unpack('HHI', data[:8], endian=self.endian), data[8:]

        self.type = self.Type(type_)
        self.arch = Architecture(arch)

        assert version == 1, 'Invalid version'

        if self.bits == 32:
            format = 'IIIIHHHHHH'
        else:
            format = 'QQQIHHHHHH'

        format_size = pack_size(format)
        (self.entry, self.phoff, self.shoff, self.flags, self.hsize, self.phentsize,
            self.phnum, self.shentsize, self.shnum, self.shstrndx) = \
            unpack(format, data[:format_size], target=self)

    def read_section(self, section):
        self.f.seek(section['offset'])
        return self.f.read(section['size'])

    def load_section_header(self, index):
        return self.parse_section_header(self.read_section_header(index))

    def read_section_header(self, index):
        self.f.seek(self.shoff + index * self.shentsize)
        return self.f.read(self.shentsize)

    def parse_section_header(self, data):
        if self.bits == 32:
            format = 'I' * 10
        else:
            format = 'IIQQQQIIQQ'

        format_size = pack_size(format)
        section = {
            key: value
            for key, value in zip(
                [
                    'name_index',
                    'type_id',
                    'flags',
                    'addr',
                    'offset',
                    'size',
                    'link',
                    'info',
                    'addralign',
                    'entsize',
                ],
                unpack(format, data[:format_size], target=self)
            )
        }

        if self.raw_section_strings is not None:
            name_index = section['name_index']
            name = self.raw_section_strings[name_index:].split('\0', 1)[0]
            self.strings[name_index] = name
        else:
            name = None

        try:
            type_ = self.SectionType(section['type_id'])
        except ValueError:
            type_ = self.SectionType.UNKNOWN

        section.update({
            'type': type_,
            'name': name,
        })

        return section

    def get_section(self, section):
        if type(section) is int:
            return self.sections_by_index[section]
        else:
            return self.sections_by_name[section]

    def symbols(self):
        dynstrs = self.read_section(self.get_section('.dynstr')).decode('ascii')
        dynsyms = self.read_section(self.get_section('.dynsym'))

        if self.bits == 32:
            fmt = 'IIIBBH'
            fmt_size = pack_size(fmt)
        else:
            fmt = 'IBBHQQ'
            fmt_size = pack_size(fmt)

        symbols = []

        while dynsyms:
            dynsym, dynsyms = dynsyms[:fmt_size], dynsyms[fmt_size:]
            if self.bits == 32:
                st_name, st_value, st_size, st_info, st_other, st_shndx = unpack(fmt, dynsym)
            else:
                st_name, st_info, st_other, st_shndx, st_value, st_size = unpack(fmt, dynsym)
            name = dynstrs[st_name:].split('\0', 1)[0]

            symbols.append({
                'name': name,
                'name_index': st_name,
                'info': st_info,
                'other': st_other,
                'shndx': st_shndx,
                'value': st_value,
                'size': st_size,
                'binding': ELF.SymbolBinding(st_info >> 4),
                'type': ELF.SymbolType(st_info & 15),
                'visibility': ELF.SymbolVisibility(st_other & 3),
            })

        return symbols
