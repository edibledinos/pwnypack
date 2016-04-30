"""
The ROP module contains a function to find gadgets in ELF binaries that can
be used to create ROP chains.
"""

from __future__ import print_function
import argparse
import re
import six
import sys
import pwnypack.codec
import pwnypack.elf
import pwnypack.main
import pwnypack.asm
import pwnypack.target
import pwnypack.util

try:
    import capstone
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False


__all__ = [
    'find_gadget',
]


if HAVE_CAPSTONE:
    INVALID_GROUPS = set((capstone.CS_GRP_CALL, capstone.CS_GRP_JUMP))


def find_gadget(elf, gadget, align=1, unique=True):
    """
    Find a ROP gadget in a the executable sections of an ELF executable or
    library. The ROP gadget can be either a set of bytes for an exact match
    or a (bytes) regular expression. Once it finds gadgets, it uses the
    capstone engine to verify if the gadget consists of valid instructions
    and doesn't contain any call or jump instructions.

    Args:
        elf(:class:`~pwnypack.elf.ELF`): The ELF instance to find a gadget in.
        gadget(bytes or regexp): The gadget to find.
        align(int): Make sure the gadget starts at a multiple of this number
        unique(bool): If true, only unique gadgets are returned.

    Returns:
        dict: A dictionary containing a description of the found
            gadget. Contains the following fields:

            - section: The section the gadget was found in.
            - offset: The offset inside the segment the gadget was found at.
            - addr: The virtual memory address the gadget will be located at.
            - gadget: The machine code of the found gadget.
            - asm: A list of disassembled instructions.

    """

    if not HAVE_CAPSTONE:
        raise NotImplementedError('pwnypack requires capstone to find ROP gadgets')

    if not isinstance(elf, pwnypack.elf.ELF):
        elf = pwnypack.elf.ELF(elf)

    matches = []
    gadgets = []

    if isinstance(gadget, six.binary_type):
        gadget = re.compile(re.escape(gadget))

    for section in elf.section_headers:
        if section.type != section.Type.progbits:
            continue

        for match in gadget.finditer(section.content):
            match_index = match.start()
            if match_index % align != 0:
                continue

            match_gadget = match.group()

            if match_gadget in gadgets:
                continue

            match_addr = section.addr + match_index

            md = pwnypack.asm.prepare_capstone(syntax=pwnypack.asm.AsmSyntax.intel, target=elf)
            md.detail = True
            match_asm = []

            for insn in md.disasm(match_gadget, match_addr):
                if insn.id == capstone.CS_OP_INVALID or set(insn.groups) & INVALID_GROUPS:
                    # Don't try to disassemble this particular gadget again.
                    gadgets.append(match_gadget)
                    break
                match_asm.append((insn.mnemonic + ' ' + insn.op_str).strip())
            else:
                matches.append({
                    'section': section,
                    'offset': match_index,
                    'addr': match_addr,
                    'gadget': match_gadget,
                    'asm': match_asm,
                })
                if unique:
                    gadgets.append(match_gadget)

    return matches


@pwnypack.main.register('gadget')
def gadget_app(_parser, cmd, args):  # pragma: no cover
    """
    Find ROP gadgets in an ELF binary.
    """

    parser = argparse.ArgumentParser(
        prog=_parser.prog,
        description=_parser.description,
    )
    parser.add_argument('file', help='ELF file to find gadgets in')
    parser.add_argument('gadget', help='the assembler source or reghex expression')
    parser.add_argument(
        '--reghex', '-r',
        dest='mode',
        action='store_const',
        const='reghex',
        help='use reghex expression (hex bytes interspaced with ? for wildcard)',
    )
    parser.add_argument(
        '--asm', '-a',
        dest='mode',
        action='store_const',
        const='asm',
        help='use assembler expression (separate lines with semi-colon)',
    )
    parser.add_argument(
        '--all', '-l',
        dest='unique',
        action='store_const',
        const=False,
        default=True,
        help='also show non-unique gadgets',
    )
    args = parser.parse_args(args)

    if args.mode is None:
        try:
            pwnypack.util.reghex(args.gadget)
            args.mode = 'reghex'
        except SyntaxError:
            args.mode = 'asm'

    elf = pwnypack.elf.ELF(args.file)

    if args.mode == 'reghex':
        try:
            gadget = pwnypack.util.reghex(args.gadget)
        except SyntaxError:
            print('Invalid reghex pattern.')
            sys.exit(1)
    else:
        try:
            gadget = pwnypack.util.reghex('*'.join([
                pwnypack.codec.enhex(pwnypack.asm.asm(piece.replace(';', '\n'), target=elf))
                for piece in ';'.join([line.strip() for line in args.gadget.split(';')]).split('*')
            ]))
        except SyntaxError as e:
            print('Could not assemble:', e.msg)
            sys.exit(1)

    matches = find_gadget(
        elf,
        gadget,
        unique=args.unique
    )

    if not matches:
        print('No gadgets found.', file=sys.stdout)
        return

    longest_gadget = max(len(m['gadget']) for m in matches)
    fmt = '  0x%%0%dx: [ %%-%ds ] %%s' % (elf.bits / 4, longest_gadget * 3 - 1)

    current_section = None

    for match in matches:
        if match['section'].name != current_section:
            if current_section is not None:
                print()
            print('Section: %s' % match['section'].name)
            current_section = match['section'].name

        hex_gadget = pwnypack.codec.enhex(match['gadget'])
        print(fmt % (
            match['addr'],
            ' '.join(
                hex_gadget[i:i+2]
                for i in range(0, len(hex_gadget), 2)
            ),
            ' ; '.join(match['asm'])
        ))

    print()
