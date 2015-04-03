"""
This module contains a parser for, and methods to extract information from
ELF files.
"""

from pwnypack.target import Target
from pwnypack.packing import U16, U32, unpack, pack_size
import pwnypack.main
from enum import IntEnum


__all__ = [
    'ELF',
]


class ELF(Target):
    """
    A parser for ELF files. Upon parsing the ELF headers, it will not only
    fill the ELF specific fields but will also populate the inherited
    :attr:`~pwnypack.target.Target.arch`, :attr:`~pwnypack.target.Target.bits`
    and :attr:`~pwnypack.target.Target.endian` properties based on the
    values it encounters.

    Arguments:
        f(str, file or ``None``): The (path to) the ELF file to parse.

    Example:
        >>> from pwny import *
        >>> e = ELF('my-executable')
        >>> print(e.machine)
        >>> print(e.program_headers)
        >>> print(e.section_headers)
        >>> print(e.symbols)
    """

    class ProgramHeader(object):
        """
        Describes how the loader will load a part of a file. Called by the
        :class:`ELF` class.

        Args:
            elf(ELF): The ELF instance owning this program header.
            data: The content of the program header entry.
        """

        class Type(IntEnum):
            """
            The segment type.
            """

            unknown = -1               #: Unknown type, check type_id for exact type
            null = 0                   #: The element is unused
            load = 1                   #: The element contains a loadable segment
            dynamic = 2                #: The element contains dynamic linking information
            interp = 3                 #: The element contains the path of the interpreter
            note = 4                   #: The element contains auxiliary information
            shlib = 5                  #: This element type is reserved
            phdr = 6                   #: This element contains the program header table itself
            gnu_eh_frame = 0x6474e550  #: This element contains the exception handler unwind information
            gnu_stack = 0x6474e551     #: This element describes the access right of the stack
            gnu_relro = 0x6474e552     #: This element contains the readonly relocations

        class Flags(IntEnum):
            """
            The individual flags that make up :attr:`ELF.ProgramHeader.flags`.
            """

            x = 1                  #: Segment is executable
            w = 2                  #: Segment is writable
            r = 4                  #: Segment is readable

        type = None     #: The type of the segment (:class:`~ELF.ProgramHeader.Type`).
        type_id = None  #: The numerical type describing the segment.
        offset = None   #: Where in the file the segment is located.
        vaddr = None    #: The virtual address at which the segment is loaded.
        paddr = None    #: The physical address at which the segment is loaded.
        filesz = None   #: The size of the segment in the file.
        memsz = None    #: The size of the segment in memory.
        flags = None    #: The flags for the segment (OR'ed values of :class:`~ELF.ProgramHeader.Flags`).
        align = None    #: The alignment of the segment.

        def __init__(self, elf, data):
            if elf.bits == 32:
                fmt = 'IIIIIIII'
                fmt_fields = [
                    'type_id',
                    'offset',
                    'vaddr',
                    'paddr',
                    'filesz',
                    'memsz',
                    'flags',
                    'align',
                ]
            else:
                fmt = 'IIQQQQQQ'
                fmt_fields = [
                    'type_id',
                    'flags',
                    'offset',
                    'vaddr',
                    'paddr',
                    'filesz',
                    'memsz',
                    'align',
                ]
            fmt_size = pack_size(fmt)

            for key, value in zip(
                fmt_fields,
                unpack(fmt, data[:fmt_size], target=elf)
            ):
                setattr(self, key, value)

            try:
                self.type = self.Type(self.type_id)
            except ValueError:
                self.type = self.Type.unknown

    class SectionHeader(object):
        """
        Describes a section of an ELF file. Called by the :class:`ELF` class.

        Args:
            elf(ELF): The ELF instance owning this section header.
            data: The content of the section header entry.
        """

        class Type(IntEnum):
            """
            Describes the section's type
            """

            unknown = -1                  #: Unknown section type
            null = 0                      #: Inactive section header
            progbits = 1                  #: Program defined information
            symtab = 2                    #: Full symbol table
            strtab = 3                    #: String table
            rela = 4                      #: Relocation entries with explicit addends
            hash = 5                      #: Symbol hash table
            dynamic = 6                   #: Dynamic linking information
            note = 7                      #: Vendor or system specific notes
            nobits = 8                    #: Occupies no file space, initialised to 0
            rel = 9                       #: Relocation entries without explicit addends
            dynsym = 11                   #: Minimal symbol table for dynamic linking
            init_array = 14               #: Array of initialisation functions
            fini_array = 15               #: Array of termination functions
            preinit_array = 16            #: Array of initialisation functions
            group = 17                    #: Section group
            symtab_shndx = 18             #: Extended symbol section mapping table
            num = 19                      #: Number of defined types

            checksum = 0x6ffffff8         #: Checksum for DSO content

            # Sun extensions:
            sunw_move = 0x6ffffffa        #: SUN extension: Additional information for partially initialized data.
            sunw_comdat = 0x6ffffffb      #: SUN extension
            sunw_syminfo = 0x6ffffffc     #: SUN extension: Extra symbol information.

            # GNU extensions:
            gnu_attributes = 0x6ffffff5   #: GNU extension: Object attributes
            gnu_hash = 0x6ffffff6         #: GNU extension: GNU-style hash section
            gnu_liblist = 0x6ffffff7      #: GNU extension: Pre-link library list
            gnu_object_only = 0x6ffffff8  #: GNU extension
            gnu_verdef = 0x6ffffffd       #: GNU extension: Version definition section
            gnu_verneed = 0x6ffffffe      #: GNU extension: Version requirements section
            gnu_versym = 0x6fffffff       #: GNU extension: Version symbol table

        class Flags(IntEnum):
            write = 1 << 0             #: Section is writable
            alloc = 1 << 1             #: Section occupies memory during execution
            execinstr = 1 << 2         #: Section contains executable code
            merge = 1 << 4             #: Section might be merged
            strings = 1 << 5           #: Section contains NUL terminated strings
            info_link = 1 << 6         #: Section's :attr:`~ELF.SectionHeader.info` field contains SHT index
            link_order = 1 << 7        #: Preserve section order after combining
            os_nonconforming = 1 << 8  #: Non-standard OS-specific handling required
            group = 1 << 9             #: Section is member of a group
            tls = 1 << 10              #: Section holds thread-local data
            maskos = 0x0ff00000        #: Mask for OS specific flags
            maskproc = 0xf0000000      #: Mask for processor specific flags
            ordered = 1 << 30          #: Treat sh_link, sh_info specially
            exclude = 1 << 31          #: Exclude section from linking

        elf = None         #: The instance of :class:`ELF` this symbol belongs to

        name = None        #: The name of this section
        name_index = None  #: The index into the string table for this section's name
        type = None        #: The type of this section (one of :class:`~ELF.SectionHeader.Type`
        type_id = None     #: The numeric identifier of the section type
        flags = None       #: The flags for this section, see :class:`~ELF.SectionHeader.Flags`
        addr = None        #: The memory address at which this section will be loaded
        offset = None      #: The offset in the file where this section resides
        size = None        #: The size of this section in the file
        link = None        #: Holds a section type dependant section header table index link
        info = None        #: Holds section type dependant extra information
        addralign = None   #: Address alignment constraint
        entsize = None     #: Size of the entries in this section

        _content = None

        def __init__(self, elf, data):
            self.elf = elf

            if elf.bits == 32:
                fmt = 'IIIIIIIIII'
            else:
                fmt = 'IIQQQQIIQQ'
            fmt_size = pack_size(fmt)

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
                unpack(fmt, data[:fmt_size], target=elf)
            ):
                setattr(self, key, value)

            try:
                self.type = self.Type(self.type_id)
            except ValueError:
                self.type = self.Type.unknown

        @property
        def content(self):
            """
            The contents of this section.
            """

            if self._content is None:
                self.elf.f.seek(self.offset)
                self._content = self.elf.f.read(self.size)

            return self._content

    class Symbol(object):
        """
        Contains information about symbols. Called by the :class:`ELF` class.

        Args:
            elf(ELF): The ELF instance owning this symbol.
            data: The content of the symbol definition.
            strs: The content of the string section associated with the symbol table.
        """

        class Binding(IntEnum):
            """
            Describes a symbol's binding.
            """

            local = 0    #: Local symbol
            global_ = 1  #: Global symbol
            weak = 2     #: Weak symbol

        class Type(IntEnum):
            """
            Describes the symbol's type.
            """

            unknown = -1  #: Symbol has an unknown type
            notype = 0    #: Symbol has no type
            object = 1    #: Symbol is an object
            func = 2      #: Symbol is a function or contains other executable code
            section = 3   #: Symbol is associated with a section
            file = 4      #: Contains the name of the source file
            common = 5    #: The symbol labels an uninitialized common block
            tls = 6       #: The symbol specifies a Thread-Local Storage entity

        class Visibility(IntEnum):
            """
            Describes the symbol's visibility.
            """

            default = 0    #: Global and weak symbols are visible, local symbols are hidden
            internal = 1   #: Symbol is an internal symbol
            hidden = 2     #: Symbol is invisible to other components
            protected = 3  #: Symbol is visible but not preemptable

        class SpecialSection(IntEnum):
            """
            Special section types.
            """

            undef = 0        #: Symbol is undefined and will be resolved by the runtime linker
            abs = 0xfff1     #: Symbol has an absolute value that will not change because of relocation
            common = 0xfff2  #: Symbol labels a common block that has not yet been allocated.

        elf = None         #: The instance of :class:`ELF` this symbol belongs to

        name_index = None  #: The index of the symbol's name in the string table
        value = None       #: The value of the symbol (type dependent)
        size = None        #: The size of the symbol
        info = None        #: Describes the symbol's type and binding (see :attr:`~ELF.Symbol.type` and
                           #: :attr:`ELF.Symbol.binding`)
        other = None       #: Specifies the symbol's visibility
        shndx = None
        """
        The section in which this symbol is defined (or one of the :class:`~ELF.Symbol.SpecialSection` types)
        """

        name = None        #: The resolved name of this symbol
        type_id = None     #: The numerical type of this symbol
        type = None        #: The resolved type of this symbol (one of :class:`~ELF.Symbol.Type`)
        visibility = None  #: The visibility of this symbol (one of :class:`~ELF.Symbol.Visibility`)

        _content = None

        def __init__(self, elf, data, strs):
            self.elf = elf

            if elf.bits == 32:
                fmt = 'IIIBBH'
            else:
                fmt = 'IBBHQQ'

            if elf.bits == 32:
                self.name_index, self.value, self.size, self.info, self.other, self.shndx = \
                    unpack(fmt, data, target=elf)
            else:
                self.name_index, self.info, self.other, self.shndx, self.value, self.size = \
                    unpack(fmt, data, target=elf)

            self.type_id = self.info & 15
            self.binding = self.Binding(self.info >> 4)
            self.visibility = self.Visibility(self.other & 3)

            self.name = strs[self.name_index:].split('\0', 1)[0]

            try:
                self.type = self.Type(self.type_id)
            except ValueError:
                self.type = self.Type.unknown

        @property
        def content(self):
            """
            The contents of a symbol.

            Raises:
                TypeError: If the symbol isn't defined until runtime.
            """

            if self.shndx in (self.SpecialSection.undef, self.SpecialSection.abs,
                              self.SpecialSection.common):
                raise TypeError('Symbol is not defined')

            if self._content is None:
                section_header = self.elf.get_section_header(self.shndx)
                symbol_offset = self.value - section_header.addr

                self.elf.f.seek(section_header.offset + symbol_offset)
                self._content = self.elf.f.read(self.size)

            return self._content

    class Type(IntEnum):
        """
        Describes the object type.
        """

        unknown = -1     #: Unknown object type
        none = 0         #: No file type
        relocatable = 1  #: Relocatable file
        executable = 2   #: Executable file
        shared = 3       #: Shared object file
        core = 4         #: Core file
        os = 0xfe00      #: OS specific
        proc = 0xff00    #: Processor specific

    class Machine(IntEnum):
        """
        The target machine architecture.
        """

        unknown = -1      #: Unknown architecture
        none = 0          #: No machine
        m32 = 1           #: AT&T WE 32100
        sparc = 2         #: SPARC
        i386 = 3          #: Intel 80386
        m68k = 4          #: Motorola 68000
        m88k = 5          #: Motorola 88000
        i860 = 7          #: Intel 80860
        mips = 8          #: MIPS I Architecture
        s370 = 9          #: IBM System/370 Processor
        mips_rs3_le = 10  #: MIPS RS3000 Little-endian
        parisc = 15       #: Hewlett-Packard PA-RISC
        vpp550 = 17       #: Fujitsu VPP500
        sparc32plus = 18  #: Enhanced instruction set SPARC
        i960 = 19         #: Intel 80960
        ppc = 20          #: PowerPC
        ppc64 = 21        #: 64-bit PowerPC
        s390 = 22         #: IBM System/390 Processor
        v800 = 36         #: NEC V800
        fr20 = 37         #: Fujitsu FR20
        rh32 = 38         #: TRW RH-32
        rce = 39          #: Motorola RCE
        arm = 40          #: Advanced RISC Machines ARM
        alpha = 41        #: Digital Alpha
        superh = 42       #: Hitachi SuperH
        sparcv9 = 43      #: SPARC Version 9
        tricore = 44      #: Siemens TriCore embedded processor
        arc = 45          #: Argonaut RISC Core, Argonaut Technologies Inc.
        h8_300 = 46       #: Hitachi H8/300
        h8_300h = 47      #: Hitachi H8/300H
        h8s = 48          #: Hitachi H8S
        h8_500 = 49       #: Hitachi H8/500
        ia64 = 50         #: Intel IA-64 processor architecture
        mipsx = 51        #: Stanford MIPS-X
        coldfire = 52     #: Motorola ColdFire
        m68hc12 = 53      #: Motorola M68HC12
        mma = 54          #: Fujitsu MMA Multimedia Accelerator
        pcp = 55          #: Siemens PCP
        ncpu = 56         #: Sony nCPU embedded RISC processor
        ndr1 = 57         #: Denso NDR1 microprocessor
        starcore = 58     #: Motorola Star*Core processor
        me16 = 59         #: Toyota ME16 processor
        st100 = 60        #: STMicroelectronics ST100 processor
        tinyj = 61        #: Advanced Logic Corp. TinyJ embedded processor family
        x86_64 = 62       #: AMD x86-64 architecture
        pdsp = 63         #: Sony DSP Processor
        pdp10 = 64        #: Digital Equipment Corp. PDP-10
        pdp11 = 65        #: Digital Equipment Corp. PDP-11
        fx66 = 66         #: Siemens FX66 microcontroller
        st9plus = 67      #: STMicroelectronics ST9+ 8/16 bit microcontroller
        st7 = 68          #: STMicroelectronics ST7 8-bit microcontroller
        m68hc16 = 69      #: Motorola MC68HC16 Microcontroller
        m68hc11 = 70      #: Motorola MC68HC11 Microcontroller
        m68hc08 = 71      #: Motorola MC68HC08 Microcontroller
        m68hc05 = 72      #: Motorola MC68HC05 Microcontroller
        svx = 73          #: Silicon Graphics SVx
        st19 = 74         #: STMicroelectronics ST19 8-bit microcontroller
        vax = 75          #: Digital VAX
        cris = 76         #: Axis Communications 32-bit embedded processor
        javelin = 77      #: Infineon Technologies 32-bit embedded processor
        firepath = 78     #: Element 14 64-bit DSP Processor
        zsp = 79          #: LSI Logic 16-bit DSP Processor
        mmix = 80         #: Donald Knuth's educational 64-bit processor
        huany = 81        #: Harvard University machine-independent object files
        prism = 82        #: SiTera Prism
        avr = 83          #: Atmel AVR 8-bit microcontroller
        fr30 = 84         #: Fujitsu FR30
        d10v = 85         #: Mitsubishi D10V
        d30v = 86         #: Mitsubishi D30V
        v850 = 87         #: NEC v850
        m32r = 88         #: Mitsubishi M32R
        mn10300 = 89      #: Matsushita MN10300
        mn10200 = 90      #: Matsushita MN10200
        pj = 91           #: picoJava
        openrisc = 92     #: OpenRISC 32-bit embedded processor
        arc_a5 = 93       #: ARC Cores Tangent-A5
        xtensa = 94       #: Tensilica Xtensa Architecture
        videocore = 95    #: Alphamosaic VideoCore processor
        tmm_gpp = 96      #: Thompson Multimedia General Purpose Processor
        ns32k = 97        #: National Semiconductor 32000 series
        tpc = 98          #: Tenor Network TPC processor
        snp1k = 99        #: Trebia SNP 1000 processor
        st200 = 100       #: STMicroelectronics ST200 microcontroller
        ip2k = 101        #: Ubicom IP2xxx microcontroller family
        max = 102         #: MAX Processor
        cr = 103          #: National Semiconductor CompactRISC microprocessor
        f2mc16 = 104      #: Fujitsu F2MC16
        msp430 = 105      #: Texas Instruments embedded microcontroller msp430
        blackfin = 106    #: Analog Devices Blackfin (DSP) processor
        se_c33 = 107      #: S1C33 Family of Seiko Epson processors
        sep = 108         #: Sharp embedded microprocessor
        arca = 109        #: Arca RISC Microprocessor
        unicore = 110     #: Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
        aarch64 = 183     #: 64-bit Advanced RISC Machines ARM

    class OSABI(IntEnum):
        """
        Describes the OS- or ABI-specific ELF extensions used by this file.
        """

        unknown = -1  #: Unknown ABI
        system_v = 0  #: SystemV ABI / No extensions
        hp_ux = 1     #: HP-UX ABI
        netbsd = 2    #: NetBSD ABI
        linux = 3     #: Linux ABI
        solaris = 6   #: Solaris ABI
        aix = 7       #: AIX ABI
        irix = 8      #: IRIX ABI
        freebsd = 9   #: FreeBSD ABI
        tru64 = 10    #: Compaq TRU64 Unix
        modesto = 11  #: Novell Modesto
        openbsd = 12  #: OpenBSD ABI
        openvms = 13  #: OpenVMS ABI
        nsk = 14      #: Hewlett-Packard Non-Stop Kernel
        aros = 15     #: Amiga Research OS
        arch = 64     #: Architecture specific ABI

    _ELF_MAGIC = b'\x7fELF'

    f = None  #: The ELF file.

    osabi = None        #: The OSABI (one of :class:`ELF.OSABI`).
    abi_version = None  #: The specific ABI version of the OS / ABI.
    type = None         #: The object type (one of :class:`ELF.Type`).
    machine = None      #: The machine architecture (one of :class:`ELF.Machine`).
    entry = None        #: The entry point address.
    phoff = None        #: The offset of the first program header in the file.
    shoff = None        #: The offset of the first section header in the file.
    flags = None        #: The flags. Currently, no flags are defined.
    hsize = None        #: The size of the header.
    phentsize = None    #: The size of a program header.
    phnum = None        #: The number of program headers.
    shentsize = None    #: The size of a section header.
    shnum = None        #: The number of section headers.
    shstrndx = None     #: The index of the section containing the section names.

    _section_headers_by_name = None
    _section_headers_by_index = None
    _program_headers = None
    _symbols_by_index = None
    _symbols_by_name = None

    def __init__(self, f=None):
        super(ELF, self).__init__()
        if f is not None:
            self.parse_file(f)

    def _parse_header(self, data):
        """
        Parse the ELF header in ``data`` and populate the properties.

        Args:
            data(bytes): The ELF header.
        """

        (magic, word_size, byte_order, version, osabi, abi_version, _), data = \
            unpack('4sBBBBB7s', data[:16]), data[16:]

        assert magic == self._ELF_MAGIC, 'Missing ELF magic'
        assert word_size in (1, 2), 'Invalid word size'
        assert byte_order in (1, 2), 'Invalid byte order'

        assert version == 1, 'Invalid version'

        self.osabi = self.OSABI(osabi)
        self.abi_version = abi_version

        (type_, machine, version), data = unpack('HHI', data[:8], endian=self.endian), data[8:]

        self.type = self.Type(type_)
        self.machine = ELF.Machine(machine)
        assert version == 1, 'Invalid version'

        if self.machine is ELF.Machine.i386:
            arch = Target.Arch.x86
            assert word_size == 1, 'Unexpected ELF64 for machine type x86'
            assert byte_order == 1, 'Unexpected big-endian for machine type x86'
        elif self.machine is ELF.Machine.x86_64:
            arch = Target.Arch.x86
            assert word_size == 2, 'Unexpected ELF32 for machine type x64_64'
            assert byte_order == 1, 'Unexpected big-endian for machine type x86'
        elif self.machine is ELF.Machine.arm:
            arch = Target.Arch.arm
            assert word_size == 1, 'Unexpected ELF64 for machine type arm'
        elif self.machine is ELF.Machine.aarch64:
            arch = Target.Arch.arm
            assert word_size == 2, 'Unexpected ELF32 for machine type aarch64'
        else:
            arch = Target.Arch.unknown

        self.arch = arch
        self.bits = 32 * word_size
        self.endian = byte_order - 1

        if self.bits == 32:
            fmt = 'IIIIHHHHHH'
        else:
            fmt = 'QQQIHHHHHH'

        fmt_size = pack_size(fmt)
        (self.entry, self.phoff, self.shoff, self.flags, self.hsize, self.phentsize,
            self.phnum, self.shentsize, self.shnum, self.shstrndx) = \
            unpack(fmt, data[:fmt_size], target=self)

    def parse_file(self, f):
        """
        Parse an ELF file and fill the class' properties.

        Arguments:
            f(file or str): The (path to) the ELF file to read.
        """

        if type(f) is str:
            self.f = open(f, 'rb')
        else:
            self.f = f
        self._parse_header(self.f.read(64))

    def _ensure_program_headers_loaded(self):
        if self._program_headers is not None:
            return

        self._program_headers = []

        if self.phnum:
            self.f.seek(self.phoff)
            for i in range(self.phnum):
                program_header = self.ProgramHeader(self, self.f.read(self.phentsize))
                self._program_headers.append(program_header)

    @property
    def program_headers(self):
        """
        A list of all program headers.
        """

        self._ensure_program_headers_loaded()
        return self._program_headers

    def get_program_header(self, index):
        """
        Return a specific program header by its index.

        Args:
            index(int): The program header index.

        Returns:
            :class:`~ELF.ProgramHeader`: The program header.

        Raises:
            KeyError: The specified index does not exist.
        """

        self._ensure_section_headers_loaded()
        return self._program_headers[index]

    def _ensure_section_headers_loaded(self):
        if self._section_headers_by_index is not None:
            return

        self._section_headers_by_index = []
        self._section_headers_by_name = {}

        if self.shnum:
            self.f.seek(self.shoff)
            for i in range(self.shnum):
                section_header = self.SectionHeader(self, self.f.read(self.shentsize))
                self._section_headers_by_index.append(section_header)

            strings_section = self._section_headers_by_index[self.shstrndx]
            section_strings = strings_section.content.decode('ascii')
            for section_header in self._section_headers_by_index:
                name_index = section_header.name_index
                section_header.name = name = section_strings[name_index:].split('\0', 1)[0]
                self._section_headers_by_name[name] = section_header

    @property
    def section_headers(self):
        """
        Return the list of section headers.
        """

        self._ensure_section_headers_loaded()
        return self._section_headers_by_index

    def get_section_header(self, section):
        """
        Get a specific section header by index or name.

        Args:
            section(int or str): The index or name of the section header to return.

        Returns:
            :class:`~ELF.SectionHeader`: The section header.

        Raises:
            KeyError: The requested section header does not exist.
        """

        self._ensure_section_headers_loaded()
        if type(section) is int:
            return self._section_headers_by_index[section]
        else:
            return self._section_headers_by_name[section]

    def _parse_symbols(self, syms, strs):
        symbols = []
        if self.bits == 32:
            fmt = 'IIIBBH'
        else:
            fmt = 'IBBHQQ'
        fmt_size = pack_size(fmt)

        while syms:
            sym, syms = syms[:fmt_size], syms[fmt_size:]
            symbols.append(self.Symbol(self, sym, strs))

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
            self.get_section_header(symbol_section).content,
            self.get_section_header(string_section).content.decode('ascii'),
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
            self._symbols_by_name = dict(
                (symbol.name, symbol)
                for symbol in symbols
                if symbol.name
            )

    @property
    def symbols(self):
        """
        Return a list of all symbols.
        """

        self._ensure_symbols_loaded()
        return self._symbols_by_index

    def get_symbol(self, symbol):
        """
        Get a specific symbol by index or name.

        Args:
            symbol(int or str): The index or name of the symbol to return.

        Returns:
            ELF.Symbol: The symbol.

        Raises:
            KeyError: The requested symbol does not exist.
        """

        self._ensure_symbols_loaded()
        if type(symbol) is int:
            return self._symbols_by_index[symbol]
        else:
            return self._symbols_by_name[symbol]


@pwnypack.main.register(name='symbols')
def symbols_app(parser, _, args):  # pragma: no cover
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
                if symbol.name != args.symbol:
                    continue
            else:
                if args.symbol.lower() not in symbol.name.lower():
                    continue

        if symbol.shndx == symbol.SpecialSection.undef:
            shndx = 'UND'
        elif symbol.shndx == symbol.SpecialSection.abs:
            shndx = 'ABS'
        elif symbol.shndx == symbol.SpecialSection.common:
            shndx = 'COM'
        else:
            shndx = str(symbol.shndx)

        print('0x%016x %5d %-7s %-7s %-10s %5s %s' % (
            symbol.value,
            symbol.size,
            symbol.type.name,
            symbol.binding.name,
            symbol.visibility.name,
            shndx,
            symbol.name,
        ))


@pwnypack.main.register(name='symbol-extract')
def extract_symbol_app(parser, _, args):  # pragma: no cover
    """
    Extract a symbol from an ELF file.
    """

    parser.add_argument('file', help='ELF file to extract a symbol from')
    parser.add_argument('symbol', help='the symbol to extract')
    args = parser.parse_args(args)
    return ELF(args.file).get_symbol(args.symbol).content
