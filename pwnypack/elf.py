"""
This module contains a parser for, and methods to extract information from
ELF files.
"""

from __future__ import print_function

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

    class DynamicSectionEntry(object):
        """
        Contains information about the entry in the .dynamic section.

        Args:
            type_id(int): The type id of the .dynamic section entry.
            value(int): The value of the .dynamic section entry.
        """

        class Type(IntEnum):
            """
            Describes the dynamic section entry type.
            """

            unknown = -1                   #: Unknown dynamic section entry type, check :attr:`type_id`.
            null = 0                       #: Marks the end of the dynamic section.
            needed = 1                     #: String table offset of the name of a needed dependency.
            pltrelsz = 2                   #: Total size of the relocation entries in the PLT.
            pltgot = 3                     #: Address of PLT/GOT.
            hash = 4                       #: Address of symbol hash table within SYMTAB.
            strtab = 5                     #: Address of the string table.
            symtab = 6                     #: Address of the symbol table.
            rela = 7                       #: Address of the relocation table.
            relasz = 8                     #: The size of the relocation table.
            relaent = 9                    #: The size a relocation table entry.
            strsz = 10                     #: The size of the string table.
            syment = 11                    #: The size of a symbol table entry.
            init = 12                      #: The address of the initialization function.
            fini = 13                      #: The address of the termination function.
            soname = 14                    #: String table offset for the name of the shared object.
            rpath = 15                     #: String table offset of a library search path.
            symbolic = 16                  #: Object contains symbolic bindings.
            rel = 17                       #: Similar to rela but with implicit addends.
            relsz = 18                     #: Size of the rel relocation section.
            relent = 19                    #: Size of a rel relocation section entry.
            pltrel = 20                    #: Type of relocation entry in the PLT table. Either rel or rela.
            debug = 21                     #: Used for debugging.
            textrel = 22                   #: One or more relocation entries resides in a read-only segement.
            jmprel = 23                    #: Address of relocation entries that are only associated with the PLT.
            bind_now = 24                  #: All relocations must be performed before code is executed.
            init_array = 25                #: Address of array of initialization functions.
            fini_array = 26                #: Address of array of termination functions.
            init_arraysz = 27              #: The size of the initialization function array.
            fini_arraysz = 28              #: The size of the termination function array.
            runpath = 29                   #: String table offset of a library search path.
            flags = 30                     #: Flags for this object.
            preinit_array = 32             #: Address of array of pre-initialization functions.
            preinit_arraysz = 33           #: Size of pre-initialization function array.
            max_postags = 34               #: Number of dynamic array tags.
            sunw_auxiliary = 0x6000000d    #: String table offset for one or more per-symbol, auxiliary filtees.
            sunw_rtldinf = 0x6000000e      #: Reserved for internal use by the runtime-linker.
            sunw_filter = 0x6000000e       #: String table offset for one or more per-symbol, standard filtee
            sunw_cap = 0x60000010          #: Address of the capabilities section.
            sunw_symtab = 0x60000011       #: Address of symbol table for local function symbols.
            sunw_symsz = 0x60000012        #: Combined size of regular and local symbol table.
            sunw_sortent = 0x60000013      #: Size of symbol sort entries.
            sunw_symsort = 0x60000014      #: Address of symbol sort section.
            sunw_symsortsz = 0x60000015    #: Size of symbol sort section.
            sunw_tlssort = 0x60000016      #: Address of thread local symbol sort section.
            sunw_tlssortsz = 0x60000017    #: Size of thread local symbol sort section.
            sunw_capinfo = 0x60000018      #: Address of capability requirement symbol association table.
            sunw_strpad = 0x60000019       #: Size of dynamic string table padding.
            sunw_capchain = 0x6000001a     #: Address of the array of capability family indices.
            sunw_ldmach = 0x6000001b       #: Machine architecture of the link-editor that produced this binary.
            sunw_capchainent = 0x6000001d  #: Size of the capability family index entry size.
            sunw_capchainsz = 0x6000001f   #: The size of the capability family index array.
            checksum = 0x6ffffdf8          #: A checksum of selected sections of the object.
            pltpadsz = 0x6ffffdf9          #: Size of padding of the PLT.
            moveent = 0x6ffffdfa           #: Size of move table entries.
            movesz = 0x6ffffdfb            #: Total size of move table.
            posflags_1 = 0x6ffffdfd        #: State flags applied to next dynamic section entry.
            syminsz = 0x6ffffdfe           #: Size of the symbol info table.
            syminent = 0x6ffffdff          #: Size of a sumbol info table entry.
            gnu_hash = 0x6ffffef5          #: Address of the GNU hash section.
            config = 0x6ffffefa            #: String table offset to the path of the configuration file.
            depaudit = 0x6ffffefb          #: String table offset defining an audit library.
            audit = 0x6ffffefc             #: String table offset defining an audit library.
            pltpad = 0x6ffffefd            #: Address of the padding of the PLT.
            movetab = 0x6ffffefe           #: Address of the move table.
            syminfo = 0x6ffffeff           #: Address of the symbol info table.
            relacount = 0x6ffffff9         #: Relative relocation count.
            relcount = 0x6ffffffa          #: Relative relocation count.
            flags_1 = 0x6ffffffb           #: Object-specific flags.
            verdef = 0x6ffffffc            #: Address of the version definition table.
            verdefnum = 0x6ffffffd         #: Number of entries in the version definition table.
            verneed = 0x6ffffffe           #: Address of the version dependency table.
            verneednum = 0x6fffffff        #: Number of entries in the version dependency table.
            sparc_register = 0x70000001    #: STT_SPARC_REGISTER symbol index within the symbol table.
            auxiliary = 0x7ffffffd         #: String table offset that names an auxiliary file.
            used = 0x7ffffffe              #: Same as needed.

        class Flags(IntEnum):
            """
            Flags when :attr:`~ELF.DynamicSectionEntry.type` is :attr:`~ELF.DynamicSectionEntry.Type.flags`.
            """

            origin = 1 << 0      #: $ORIGIN processing is required.
            symbolic = 1 << 1    #: Symbol resolution is required.
            textrel = 1 << 2     #: Text relocations exist.
            bind_now = 1 << 3    #: Non-lazy binding required.
            static_tls = 1 << 4  #: Object uses static thread local storage.

        class Flags_1(IntEnum):
            """
            Flags when :attr:`~ELF.DynamicSectionEntry.type` is :attr:`~ELF.DynamicSectionEntry.Type.flags_1`.
            """

            now = 1 << 0          #: Perform complete relocation processing.
            global_ = 1 << 1      #: Unused.
            group = 1 << 2        #: Object is a member of a group.
            nodelete = 1 << 3     #: Object cannot be removed from a process.
            loadfltr = 1 << 4     #: Make sure filtees are loaded immediately.
            initfirst = 1 << 5    #: Objects' initialization occurs first.
            noopen = 1 << 6       #: Object cannot be used with dlopen.
            origin = 1 << 7       #: $ORIGIN processing is required.
            direct = 1 << 8       #: Direct bindings are enabled.
            interpose = 1 << 9    #: Object is an interposer.
            nodeflib = 1 << 10    #: Ignore the default library search path.
            nodump = 1 << 11      #: Object cannot be dumped.
            confalt = 1 << 12     #: Object is a configuration alternative.
            endfiltee = 1 << 13   #: Filtee terminates filter's search.
            dispreldne = 1 << 14  #: Displacement relocation has been completed.
            disprelpnd = 1 << 15  #: Displacement relocation is pending.
            nodirect = 1 << 16    #: Object contains non-direct bindings.
            ignmuldef = 1 << 17   #: Reserved for internal use.
            noksyms = 1 << 18     #: Reserved for internal use.
            nohdr = 1 << 19       #: Reserved for internal use.
            edited = 1 << 20      #: Object has been modified since it was built.
            noreloc = 1 << 21     #: Reserved for internal use.
            symintpose = 1 << 22  #: Individual symbol interposers exist.
            globaudit = 1 << 23   #: Global auditing is enabled.
            singleton = 1 << 24   #: Singleton symbols exist.

        class Posflags_1(IntEnum):
            """
            Flags when :attr:`~ELF.DynamicSectionEntry.type` is :attr:`ELF.DynamicSectionEntry.Type.posflags_1`.
            """

            lazyload = 1 << 0   #: Identify lazily loaded dependency.
            groupperm = 1 << 1  #: Identify group dependency.

        type_id = None  #: The numerical type of this entry.
        type = None     #: The resolved type of this entry (one of :class:`~ELF.DynamicSectionEntry.Type`).
        value = None    #: The value of this entry.

        def __init__(self, type_id, value):
            self.type_id = type_id
            self.value = value

            try:
                self.type = self.Type(self.type_id)
            except ValueError:
                self.type = self.Type.unknown

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
        arm = 97      #: ARM ABI

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
    _dynamic_section_entries = None

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

        endian = Target.Endian(byte_order - 1)
        (type_, machine, version), data = unpack('HHI', data[:8], endian=endian), data[8:]

        try:
            self.type = self.Type(type_)
        except ValueError:
            self.type = self.Type.unknown

        try:
            self.machine = ELF.Machine(machine)
        except ValueError:
            self.machine = ELF.Machine.unknown

        assert version == 1, 'Invalid version'

        if self.machine is ELF.Machine.i386:
            arch = Target.Arch.x86
            assert word_size == 1, 'Unexpected ELF64 for machine type x86'
            assert endian is Target.Endian.little, 'Unexpected big-endian for machine type x86'
        elif self.machine is ELF.Machine.x86_64:
            arch = Target.Arch.x86
            assert word_size == 2, 'Unexpected ELF32 for machine type x64_64'
            assert endian is Target.Endian.little, 'Unexpected big-endian for machine type x86'
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
        self.endian = endian

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

    def _ensure_dynamic_section_loaded(self):
        if self._dynamic_section_entries is None:
            try:
                section = self.get_section_header('.dynamic')
                data = section.content
            except KeyError:
                data = []
            if self.bits == 32:
                fmt = 'iI'
            else:
                fmt = 'QQ'
            fmt_size = pack_size(fmt)
            self._dynamic_section_entries = [
                self.DynamicSectionEntry(*unpack(fmt, data[i:i + fmt_size], target=self))
                for i in range(0, len(data), fmt_size)
            ]

    @property
    def dynamic_section_entries(self):
        """
        A list of entries in the .dynamic section.
        """

        self._ensure_dynamic_section_loaded()
        return self._dynamic_section_entries

    def get_dynamic_section_entry(self, index):
        """
        Get a specific .dynamic section entry by index.

        Args:
            symbol(int): The index of the .dynamic section entry to return.

        Returns:
            ELF.DynamicSectionEntry: The .dynamic section entry.

        Raises:
            KeyError: The requested entry does not exist.
        """

        self._ensure_dynamic_section_loaded()
        return self._dynamic_section_entries[index]


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


@pwnypack.main.register(name='checksec')
def checksec_app(_parser, _, args):  # pragma: no cover
    """
    Check security features of an ELF file.
    """

    import sys
    import argparse
    import csv
    import os.path

    def checksec(elf, path, fortifiable_funcs):
        relro = 0
        nx = False
        pie = 0
        rpath = False
        runpath = False

        for header in elf.program_headers:
            if header.type == ELF.ProgramHeader.Type.gnu_relro:
                relro = 1
            elif header.type == ELF.ProgramHeader.Type.gnu_stack:
                if not header.flags & ELF.ProgramHeader.Flags.x:
                    nx = True

        if elf.type == ELF.Type.shared:
            pie = 1

        for entry in elf.dynamic_section_entries:
            if entry.type == ELF.DynamicSectionEntry.Type.bind_now and relro == 1:
                relro = 2
            elif entry.type == ELF.DynamicSectionEntry.Type.flags and \
                    entry.value & ELF.DynamicSectionEntry.Flags.bind_now:
                relro = 2
            elif entry.type == ELF.DynamicSectionEntry.Type.flags_1 and \
                    entry.value & ELF.DynamicSectionEntry.Flags_1.now:
                relro = 2
            elif entry.type == ELF.DynamicSectionEntry.Type.debug and pie == 1:
                pie = 2
            elif entry.type == ELF.DynamicSectionEntry.Type.rpath:
                rpath = True
            elif entry.type == ELF.DynamicSectionEntry.Type.runpath:
                runpath = True

        rtl_symbol_names = set(
            symbol.name
            for symbol in elf.symbols
            if symbol.name and symbol.shndx == ELF.Symbol.SpecialSection.undef
        )

        fortified = fortifiable_funcs & rtl_symbol_names
        unfortified = fortifiable_funcs & set('__%s_chk' % symbol_name for symbol_name in rtl_symbol_names)

        canary = '__stack_chk_fail' in rtl_symbol_names

        return {
            'path': path,
            'relro': relro,
            'nx': nx,
            'pie': pie,
            'rpath': rpath,
            'runpath': runpath,
            'canary': canary,
            'fortified': len(fortified),
            'unfortified': len(unfortified),
            'fortifiable': len(fortified | unfortified),
        }

    def check_paths(paths, fortifiable_funcs):
        for path in paths:
            if os.path.isdir(path):
                for data in check_paths(
                        (os.path.join(path, fn) for fn in os.listdir(path) if fn not in ('.', '..')),
                        fortifiable_funcs,
                ):
                    yield data
            else:
                try:
                    elf = ELF(path)
                except:
                    continue

                yield checksec(elf, path, fortifiable_funcs)

    parser = argparse.ArgumentParser(
        prog=_parser.prog,
        description=_parser.description,
    )
    parser.add_argument('path', nargs='+', help='ELF file to check security features of')
    parser.add_argument(
        '-f', '--format',
        dest='format',
        choices=['text', 'csv'],
        default='text',
        help='set output format'
    )
    parser.add_argument(
        '-l', '--libc',
        dest='libc',
        help='path to the applicable libc.so'
    )
    args = parser.parse_args(args)

    if args.libc:
        libc = ELF(args.libc)
        fortifiable_funcs = set([
            symbol.name
            for symbol in libc.symbols
            if symbol.name.startswith('__') and symbol.name.endswith('_chk')
        ])
    else:
        fortifiable_funcs = set('''__wctomb_chk __wcsncat_chk __mbstowcs_chk __strncpy_chk __syslog_chk __mempcpy_chk
                                   __fprintf_chk __recvfrom_chk __readlinkat_chk __wcsncpy_chk __fread_chk
                                   __getlogin_r_chk __vfwprintf_chk __recv_chk __strncat_chk __printf_chk __confstr_chk
                                   __pread_chk __ppoll_chk __ptsname_r_chk __wcscat_chk __snprintf_chk __vwprintf_chk
                                   __memset_chk __memmove_chk __gets_chk __fgetws_unlocked_chk __asprintf_chk __poll_chk
                                   __fdelt_chk __fgets_unlocked_chk __strcat_chk __vsyslog_chk __stpcpy_chk
                                   __vdprintf_chk __strcpy_chk __obstack_printf_chk __getwd_chk __pread64_chk
                                   __wcpcpy_chk __fread_unlocked_chk __dprintf_chk __fgets_chk __wcpncpy_chk
                                   __obstack_vprintf_chk __wprintf_chk __getgroups_chk __wcscpy_chk __vfprintf_chk
                                   __fgetws_chk __vswprintf_chk __ttyname_r_chk __mbsrtowcs_chk
                                   __wmempcpy_chk __wcsrtombs_chk __fwprintf_chk __read_chk __getcwd_chk __vsnprintf_chk
                                   __memcpy_chk __wmemmove_chk __vasprintf_chk __sprintf_chk __vprintf_chk
                                   __mbsnrtowcs_chk __wcrtomb_chk __realpath_chk __vsprintf_chk __wcsnrtombs_chk
                                   __gethostname_chk __swprintf_chk __readlink_chk __wmemset_chk __getdomainname_chk
                                   __wmemcpy_chk __longjmp_chk __stpncpy_chk __wcstombs_chk'''.split())

    if args.format == 'text':
        print('RELRO    CANARY  NX   PIE  RPATH  RUNPATH  FORTIFIED  PATH')
        for data in check_paths(args.path, fortifiable_funcs):
            print('{:7}  {:6}  {:3}  {:3}  {:5}  {:7}  {:>9}  {}'.format(
                ('No', 'Partial', 'Full')[data['relro']],
                'Yes' if data['canary'] else 'No',
                'Yes' if data['nx'] else 'No',
                ('No', 'DSO', 'Yes')[data['pie']],
                'Yes' if data['rpath'] else 'No',
                'Yes' if data['runpath'] else 'No',
                '{}/{}/{}'.format(data['fortified'], data['unfortified'], data['fortifiable']),
                data['path']
            ))
    else:
        writer = csv.writer(sys.stdout)
        writer.writerow(['path', 'relro', 'canary', 'nx', 'pie', 'rpath', 'runpath', 'fortified', 'unfortified',
                         'fortifiable'])
        for data in check_paths(args.path, fortifiable_funcs):
            writer.writerow([
                data['path'],
                ('no', 'partial', 'full')[data['relro']],
                'yes' if data['canary'] else 'no',
                'yes' if data['nx'] else 'no',
                ('no', 'dso', 'yes')[data['pie']],
                'yes' if data['rpath'] else 'no',
                'yes' if data['runpath'] else 'no',
                data['fortified'],
                data['unfortified'],
                data['fortifiable'],
            ])
