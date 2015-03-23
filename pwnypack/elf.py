from pwnypack.target import Architecture, Endianness, Target
from pwnypack.packing import U16, U32, unpack, pack_size
import pwnypack.main
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
        UNKNOWN = -1
        NOTYPE = 0
        OBJECT = 1
        FUNC = 2
        SECTION = 3
        FILE = 4
        COMMON = 5
        TLS = 6

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
            self.shentsize = self.shnum = self.shstrndx = None

        self._section_headers_by_name = self._section_headers_by_index = None
        self._symbols_by_index = self._symbols_by_name = None

        self.f = None
        if f is not None:
            self.parse_file(f)

    def _parse_header(self, data):
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
            fmt = 'IIIIHHHHHH'
        else:
            fmt = 'QQQIHHHHHH'

        fmt_size = pack_size(fmt)
        (self.entry, self.phoff, self.shoff, self.flags, self.hsize, self.phentsize,
            self.phnum, self.shentsize, self.shnum, self.shstrndx) = \
            unpack(fmt, data[:fmt_size], target=self)

    def parse_file(self, f):
        if type(f) is str:
            self.f = open(f, 'rb')
        else:
            self.f = f
        self._parse_header(self.f.read(64))

    def _parse_section_header(self, data):
        if self.bits == 32:
            fmt = 'I' * 10
        else:
            fmt = 'IIQQQQIIQQ'
        fmt_size = pack_size(fmt)

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
                unpack(fmt, data[:fmt_size], target=self)
            )
        }

        try:
            section['type'] = self.SectionType(section['type_id'])
        except ValueError:
            section['type'] = self.SectionType.UNKNOWN

        return section

    def _ensure_section_headers_loaded(self):
        if self._section_headers_by_index is not None:
            return

        self._section_headers_by_index = []
        self._section_headers_by_name = {}

        if self.shnum:
            self.f.seek(self.shoff)
            for i in range(self.shnum):
                section = self._parse_section_header(self.f.read(self.shentsize))
                self._section_headers_by_index.append(section)

            strings_section = self._section_headers_by_index[self.shstrndx]
            section_strings = self.read_section(strings_section).decode('ascii')
            for section in self._section_headers_by_index:
                name_index = section['name_index']
                section['name'] = name = section_strings[name_index:].split('\0', 1)[0]
                self._section_headers_by_name[name] = section

    @property
    def section_headers(self):
        self._ensure_section_headers_loaded()
        return self._section_headers_by_index

    def get_section_header(self, section):
        self._ensure_section_headers_loaded()
        if type(section) is int:
            return self._section_headers_by_index[section]
        else:
            return self._section_headers_by_name[section]

    def read_section(self, section):
        if isinstance(section, (int, str)):
            section = self.get_section_header(section)
        self.f.seek(section['offset'])
        return self.f.read(section['size'])

    def _parse_symbols(self, syms, strs):
        if self.bits == 32:
            fmt = 'IIIBBH'
        else:
            fmt = 'IBBHQQ'
        fmt_size = pack_size(fmt)

        symbols = []

        while syms:
            sym, syms = syms[:fmt_size], syms[fmt_size:]
            if self.bits == 32:
                st_name, st_value, st_size, st_info, st_other, st_shndx = unpack(fmt, sym)
            else:
                st_name, st_info, st_other, st_shndx, st_value, st_size = unpack(fmt, sym)
            name = strs[st_name:].split('\0', 1)[0]

            try:
                type_ = ELF.SymbolType(st_info & 15)
            except ValueError:
                type_ = ELF.SymbolType.UNKNOWN

            symbols.append({
                'name': name,
                'name_index': st_name,
                'info': st_info,
                'other': st_other,
                'shndx': st_shndx,
                'value': st_value,
                'size': st_size,
                'binding': ELF.SymbolBinding(st_info >> 4),
                'type_id': st_info & 15,
                'type': type_,
                'visibility': ELF.SymbolVisibility(st_other & 3),
            })

        return symbols

    def _read_symbols(self, symbol_section, string_section=None):
        if string_section is None:
            string_section = {
                '.symtab': '.strtab',
                '.dynsym': '.dynstr'
            }.get(symbol_section, None)
            if string_section is None:
                raise ValueError('Could not determine string section for symbol section %s' % symbol_section)

        return self._parse_symbols(
            self.read_section(symbol_section),
            self.read_section(string_section).decode('ascii')
        )

    def _ensure_symbols_loaded(self):
        if self._symbols_by_index is None:
            try:
                symbols = self._read_symbols('.symtab')
            except KeyError:
                try:
                    symbols = self._read_symbols('.dynsym')
                except KeyError:
                    symbols = []

            self._symbols_by_index = symbols
            self._symbols_by_name = {
                symbol['name']: symbol
                for symbol in symbols
                if symbol['name']
            }

    @property
    def symbols(self):
        self._ensure_symbols_loaded()
        return self._symbols_by_index

    def get_symbol(self, symbol):
        self._ensure_symbols_loaded()
        if type(symbol) is int:
            return self._symbols_by_index[symbol]
        else:
            return self._symbols_by_name[symbol]


@pwnypack.main.register(name='symbols')
def symbols_app(parser, cmd, args):  # pragma: no cover
    """
    List ELF symbol table.
    """

    parser.add_argument('file', help='ELF file to list the symbols of')
    parser.add_argument('symbol', nargs='?', help='show only this symbol')
    parser.add_argument('--exact', '-e', action='store_const', const=True, help='filter by exact symbol name')
    args = parser.parse_args(args)

    print('%-18s %5s %-7s %-7s %-10s %5s %s' % (
        'value',
        'size',
        'type',
        'binding',
        'visibility',
        'index',
        'name',
    ))

    elf = ELF(args.file)
    for symbol in elf.symbols:
        if args.symbol:
            if args.exact:
                if symbol['name'] != args.symbol:
                    continue
            else:
                if args.symbol.lower() not in symbol['name'].lower():
                    continue

        if symbol['shndx'] == elf.SHN_UNDEF:
            shndx = 'UND'
        elif symbol['shndx'] == elf.SHN_ABS:
            shndx = 'ABS'
        elif symbol['shndx'] == elf.SHN_COMMON:
            shndx = 'COM'
        else:
            shndx = str(symbol['shndx'])

        print('0x%016x %5d %-7s %-7s %-10s %5s %s' % (
            symbol['value'],
            symbol['size'],
            symbol['type'].name,
            symbol['binding'].name,
            symbol['visibility'].name,
            shndx,
            symbol['name'],
        ))
