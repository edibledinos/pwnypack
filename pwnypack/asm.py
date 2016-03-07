"""
This module contains functions to assemble and disassemble code for a given
target platform.

Currently, the only supported architecture is
:attr:`~pwnypack.target.Target.Arch.x86` (both 32 and 64 bits variants).
Assembly is performed by the *nasm* assembler (only supports
:attr:`~AsmSyntax.nasm` syntax). Disassembly is performed by *ndisasm*
(:attr:`~AsmSyntax.nasm` syntax) or *capstone*
(:attr:`~AsmSyntax.intel` & :attr:`~AsmSyntax.att` syntax).
"""

from __future__ import print_function
import argparse
import os
import subprocess
import sys
import capstone
from enum import IntEnum
from pwnypack.elf import ELF
import pwnypack.target
import pwnypack.main
import pwnypack.codec
import tempfile


__all__ = [
    'AsmSyntax',
    'asm',
    'disasm',
]


class AsmSyntax(IntEnum):
    """
    This enumeration is used to specify the assembler syntax.
    """

    nasm = 0   #: Netwide assembler syntax
    intel = 1  #: Intel assembler syntax
    att = 2    #: AT&T assembler syntax


def asm(code, addr=0, syntax=AsmSyntax.nasm, target=None):
    """asm(code, addr=0, syntax=AsmSyntax.nasm, target=None)

    Assemble statements into machine readable code.

    Args:
        code(str): The statements to assemble.
        addr(int): The memory address where the code will run.
        syntax(AsmSyntax): The input assembler syntax.
        target(~pwnypack.target.Target): The target architecture. The
            global target is used if this argument is ``None``.

    Returns:
        bytes: The assembled machine code.

    Raises:
        SyntaxError: If the assembler statements are invalid.
        NotImplementedError: In an unsupported target platform is specified.

    Example:
        >>> from pwny import *
        >>> asm('''
        ...     pop rdi
        ...     ret
        ... ''', target=Target(arch=Target.Arch.x86, bits=64))
        b'_\\xc3'
    """

    if target is None:
        target = pwnypack.target.target

    if syntax is AsmSyntax.nasm:
        if target.arch is not pwnypack.target.Target.Arch.x86:
            raise NotImplementedError('nasm only supports x86 target platforms.')

        with tempfile.NamedTemporaryFile() as tmp_asm:
            tmp_asm.write(('bits %d\norg %d\n%s' % (target.bits.value, addr, code)).encode('utf-8'))
            tmp_asm.flush()

            tmp_bin_fd, tmp_bin_name = tempfile.mkstemp()
            os.close(tmp_bin_fd)

            try:
                p = subprocess.Popen(
                    [
                        'nasm',
                        '-o', tmp_bin_name,
                        '-f', 'bin',
                        tmp_asm.name,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                stdout, stderr = p.communicate()

                if p.returncode:
                    raise SyntaxError(stderr.decode('utf-8'))

                tmp_bin = open(tmp_bin_name, 'rb')
                result = tmp_bin.read()
                tmp_bin.close()
                return result
            finally:
                try:
                    os.unlink(tmp_bin_name)
                except OSError:
                    pass
    else:
        raise NotImplementedError('Unsupported syntax for host platform.')


def prepare_capstone(syntax=AsmSyntax.att, target=None):
    """
    Prepare a capstone disassembler instance for a given target and syntax.

    Args:
        syntax(AsmSyntax): The assembler syntax (Intel or AT&T).
        target(~pwnypack.target.Target): The target to create a disassembler
            instance for. The global target is used if this argument is
            ``None``.

    Returns:
        An instance of the capstone disassembler.

    Raises:
        NotImplementedError: If the specified target isn't supported.
    """

    if target is None:
        target = pwnypack.target.target

    if target.arch == pwnypack.target.Target.Arch.x86:
        if target.bits is pwnypack.target.Target.Bits.bits_32:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        else:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        raise NotImplementedError('Only x86 is currently supported.')

    md.skipdata = True

    if syntax is AsmSyntax.att:
        md.syntax = capstone.CS_OPT_SYNTAX_ATT
    elif syntax is AsmSyntax.intel:
        md.skipdata_setup(('db', None, None))
    else:
        raise NotImplementedError('capstone engine only implements AT&T and Intel syntax.')

    return md


def disasm(code, addr=0, syntax=AsmSyntax.nasm, target=None):
    """disasm(code, addr=0, syntax=AsmSyntax.nasm, target=None)

    Disassemble machine readable code into human readable statements.

    Args:
        code(bytes): The machine code that is to be disassembled.
        addr(int): The memory address of the code (used for relative
            references).
        syntax(AsmSyntax): The output assembler syntax.
        target(~pwnypack.target.Target): The architecture for which the code
            was written.  The global target is used if this argument is
            ``None``.

    Returns:
        list of str: The disassembled machine code.

    Raises:
        NotImplementedError: In an unsupported target platform is specified.
        RuntimeError: If ndisasm encounters an error.

    Example:
        >>> from pwny import *
        >>> disasm(b'_\\xc3', target=Target(arch=Target.Arch.x86, bits=64))
        ['pop rdi', 'ret']
    """

    if target is None:
        target = pwnypack.target.target

    if syntax is AsmSyntax.nasm:
        if target.arch is not pwnypack.target.Target.Arch.x86:
            raise NotImplementedError('nasm only supports x86.')

        p = subprocess.Popen(
            [
                'ndisasm',
                '-b',
                str(target.bits.value),
                '-o',
                str(addr),
                '-',
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = p.communicate(code)
        if p.returncode:
            raise RuntimeError(stderr.decode('utf-8'))

        return [
            line.split(None, 2)[2]
            for line in stdout.decode('utf-8').split('\n')
            if line and not line.startswith(' ')
        ]
    elif syntax in (AsmSyntax.intel, AsmSyntax.att):
        md = prepare_capstone(syntax, target)
        statements = []
        total_size = 0
        for (_, size, mnemonic, op_str) in md.disasm_lite(code, addr):
            statements.append((mnemonic + ' ' + op_str).strip())
            total_size += size
        return statements
    else:
        raise NotImplementedError('Unsupported syntax for host platform.')


@pwnypack.main.register('asm')
def asm_app(parser, cmd, args):  # pragma: no cover
    """
    Assemble code from commandline or stdin.

    Please not that all semi-colons are replaced with carriage returns
    unless source is read from stdin.
    """

    parser.add_argument('source', help='the code to assemble, read from stdin if omitted', nargs='?')
    pwnypack.main.add_target_arguments(parser)
    parser.add_argument(
        '--syntax', '-s',
        choices=AsmSyntax.__members__.keys(),
        default='nasm',
    )
    parser.add_argument(
        '--address', '-o',
        type=lambda v: int(v, 0),
        default=0,
        help='the address where the code is expected to run',
    )

    args = parser.parse_args(args)
    target = pwnypack.main.target_from_arguments(args)
    syntax = AsmSyntax.__members__[args.syntax]
    if args.source is None:
        args.source = sys.stdin.read()
    else:
        args.source = args.source.replace(';', '\n')

    return asm(
        args.source,
        syntax=syntax,
        target=target,
    )


@pwnypack.main.register('disasm')
def disasm_app(_parser, cmd, args):  # pragma: no cover
    """
    Disassemble code from commandline or stdin.
    """

    parser = argparse.ArgumentParser(
        prog=_parser.prog,
        description=_parser.description,
    )
    parser.add_argument('code', help='the code to disassemble, read from stdin if omitted', nargs='?')
    pwnypack.main.add_target_arguments(parser)
    parser.add_argument(
        '--syntax', '-s',
        choices=AsmSyntax.__members__.keys(),
        default='nasm',
    )
    parser.add_argument(
        '--address', '-o',
        type=lambda v: int(v, 0),
        default=0,
        help='the address of the disassembled code',
    )
    parser.add_argument(
        '--format', '-f',
        choices=['hex', 'bin'],
        help='the input format (defaults to hex for commandline, bin for stdin)',
    )

    args = parser.parse_args(args)
    target = pwnypack.main.target_from_arguments(args)
    syntax = AsmSyntax.__members__[args.syntax]

    if args.format is None:
        if args.code is None:
            args.format = 'bin'
        else:
            args.format = 'hex'

    if args.format == 'hex':
        code = pwnypack.codec.dehex(pwnypack.main.string_value_or_stdin(args.code))
    else:
        code = pwnypack.main.binary_value_or_stdin(args.code)

    print('\n'.join(disasm(code, args.address, syntax=syntax, target=target)))


@pwnypack.main.register(name='symbol-disasm')
def disasm_symbol_app(_parser, _, args):  # pragma: no cover
    """
    Disassemble a symbol from an ELF file.
    """

    parser = argparse.ArgumentParser(
        prog=_parser.prog,
        description=_parser.description,
    )
    parser.add_argument(
        '--syntax', '-s',
        choices=AsmSyntax.__members__.keys(),
        default='nasm',
    )
    parser.add_argument('file', help='ELF file to extract a symbol from')
    parser.add_argument('symbol', help='the symbol to disassemble')

    args = parser.parse_args(args)
    syntax = AsmSyntax.__members__[args.syntax]
    elf = ELF(args.file)
    symbol = elf.get_symbol(args.symbol)
    print('\n'.join(disasm(symbol.content, symbol.value, syntax=syntax, target=elf)))
