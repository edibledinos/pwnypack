"""
This module contains functions to assemble and disassemble code for a given
target platform. By default the keystone engine assembler will be used if it
is available. If it's not available (or if the ``WANT_KEYSTONE`` environment
variable is set and it's not ``1``, ``YES`` or ``TRUE`` (case insensitive)),
pwnypack falls back to using the *nasm* assembler for nasm syntax on X86 or
*GNU as* for any other supported syntax / architecture. Disassembly is
performed by *ndisasm* on x86 for nasm syntax. *capstone* is used for any
other supported syntax / architecture.

Currently, the only supported architectures are
:attr:`~pwnypack.target.Target.Arch.x86` (both 32 and 64 bits variants) and
:attr:`~pwnypack.target.Target.Arch.arm` (both 32 and 64 bits variants).
"""

from __future__ import print_function

try:
    import shutilwhich
except ImportError:
    pass

import argparse
import os
import subprocess
import sys
from enum import IntEnum
import shutil
from pwnypack.elf import ELF
import pwnypack.target
import pwnypack.main
import pwnypack.codec
import tempfile
import six

try:
    import capstone
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False

try:
    import keystone
    HAVE_KEYSTONE = True
except ImportError:
    HAVE_KEYSTONE = False
WANT_KEYSTONE = os.environ.get('WANT_KEYSTONE', '1').upper() in ('1', 'YES', 'TRUE')


__all__ = [
    'AsmSyntax',
    'asm',
    'disasm',
]


BINUTILS_SUFFIXES = [
    'none-eabi-',
    'unknown-linux-gnu-',
    'linux-gnu-',
    'linux-gnueabi-',
]
BINUTILS_PREFIXES = {}


def find_binutils_prefix(arch):
    global BINUTILS_PREFIXES

    prefix = BINUTILS_PREFIXES.get(arch)
    if prefix is not None:
        return prefix

    for suffix in BINUTILS_SUFFIXES:
        prefix = '%s-%s' % (arch, suffix)
        if shutil.which('%sas' % prefix) and \
                shutil.which('%sld' % prefix):
            BINUTILS_PREFIXES[arch] = prefix
            return prefix
    else:
        raise RuntimeError('Could not locate a suitable binutils for %s.' % arch)


class AsmSyntax(IntEnum):
    """
    This enumeration is used to specify the assembler syntax.
    """

    nasm = 0   #: Netwide assembler syntax
    intel = 1  #: Intel assembler syntax
    att = 2    #: AT&T assembler syntax


def asm(code, addr=0, syntax=None, target=None, gnu_binutils_prefix=None):
    """
    Assemble statements into machine readable code.

    Args:
        code(str): The statements to assemble.
        addr(int): The memory address where the code will run.
        syntax(AsmSyntax): The input assembler syntax for x86. Defaults to
            nasm, ignored on other platforms.
        target(~pwnypack.target.Target): The target architecture. The
            global target is used if this argument is ``None``.
        gnu_binutils_prefix(str): When the syntax is AT&T, gnu binutils'
            as and ld will be used. By default, it selects
            ``arm-*-as/ld`` for 32bit ARM targets,
            ``aarch64-*-as/ld`` for 64 bit ARM targets,
            ``i386-*-as/ld`` for 32bit X86 targets and
            ``amd64-*-as/ld`` for 64bit X86 targets (all for various flavors
            of ``*``. This option allows you to pick a different toolchain.
            The prefix should always end with a '-' (or be empty).

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

    if syntax is None and target.arch is pwnypack.target.Target.Arch.x86:
        syntax = AsmSyntax.nasm

    if HAVE_KEYSTONE and WANT_KEYSTONE:
        ks_mode = 0
        ks_syntax = None

        if target.arch is pwnypack.target.Target.Arch.x86:
            ks_arch = keystone.KS_ARCH_X86
            if target.bits is pwnypack.target.Target.Bits.bits_32:
                ks_mode |= keystone.KS_MODE_32
            else:
                ks_mode |= keystone.KS_MODE_64
            if syntax is AsmSyntax.nasm:
                ks_syntax = keystone.KS_OPT_SYNTAX_NASM
            elif syntax is AsmSyntax.intel:
                ks_syntax = keystone.KS_OPT_SYNTAX_INTEL
            else:
                ks_syntax = keystone.KS_OPT_SYNTAX_ATT

        elif target.arch is pwnypack.target.Target.Arch.arm:
            if target.bits is pwnypack.target.Target.Bits.bits_32:
                ks_arch = keystone.KS_ARCH_ARM

                if target.mode & pwnypack.target.Target.Mode.arm_thumb:
                    ks_mode |= keystone.KS_MODE_THUMB
                else:
                    ks_mode |= keystone.KS_MODE_ARM

                if target.mode & pwnypack.target.Target.Mode.arm_v8:
                    ks_mode |= keystone.KS_MODE_V8

                if target.mode & pwnypack.target.Target.Mode.arm_m_class:
                    ks_mode |= keystone.KS_MODE_MICRO

                if target.endian is pwnypack.target.Target.Endian.little:
                    ks_mode |= keystone.KS_MODE_LITTLE_ENDIAN
                else:
                    ks_mode |= keystone.KS_MODE_BIG_ENDIAN
            else:
                ks_arch = keystone.KS_ARCH_ARM64
                ks_mode |= keystone.KS_MODE_BIG_ENDIAN
        else:
            raise NotImplementedError('Unsupported syntax or target platform.')

        ks = keystone.Ks(ks_arch, ks_mode)
        if ks_syntax is not None:
            ks.syntax = ks_syntax
        try:
            data, insn_count = ks.asm(code, addr)
        except keystone.KsError as e:
            import traceback
            traceback.print_exc()
            raise SyntaxError(e.message)
        return b''.join(six.int2byte(b) for b in data)

    if target.arch is pwnypack.target.Target.Arch.x86 and syntax is AsmSyntax.nasm:
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
    elif target.arch in (pwnypack.target.Target.Arch.x86, pwnypack.target.Target.Arch.arm):
        preamble = ''
        as_flags = []
        ld_flags = []

        if target.arch is pwnypack.target.Target.Arch.x86:
            if target.bits == 32:
                binutils_arch = 'i386'
            else:
                binutils_arch = 'amd64'

            if syntax is AsmSyntax.intel:
                preamble = '.intel_syntax noprefix\n'

            ld_flags.extend(['--oformat', 'binary'])
        else:
            if target.bits == 32:
                binutils_arch = 'arm'
                if target.mode & pwnypack.target.Target.Mode.arm_v8:
                    as_flags.append('-march=armv8-a')
                elif target.mode & pwnypack.target.Target.Mode.arm_m_class:
                    as_flags.append('-march=armv7m')
            else:
                binutils_arch = 'aarch64'

            if target.endian is pwnypack.target.Target.Endian.little:
                as_flags.append('-mlittle-endian')
                ld_flags.append('-EL')
            else:
                as_flags.append('-mbig-endian')
                ld_flags.append('-EB')

            if target.mode & pwnypack.target.Target.Mode.arm_thumb:
                as_flags.append('-mthumb')

        if gnu_binutils_prefix is None:
            gnu_binutils_prefix = find_binutils_prefix(binutils_arch)

        tmp_out_fd, tmp_out_name = tempfile.mkstemp()
        try:
            os.close(tmp_out_fd)

            p = subprocess.Popen(
                [
                    '%sas' % gnu_binutils_prefix,
                    '-o', tmp_out_name
                ] + as_flags,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = p.communicate((preamble + code).encode('utf-8'))

            if p.returncode:
                raise SyntaxError(stderr.decode('utf-8'))

            tmp_bin_fd, tmp_bin_name = tempfile.mkstemp()
            try:
                os.close(tmp_bin_fd)

                p = subprocess.Popen(
                    [
                        '%sld' % gnu_binutils_prefix,
                        '-Ttext', str(addr),
                    ] + ld_flags + [
                        '-o', tmp_bin_name,
                        tmp_out_name,
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                stdout, stderr = p.communicate()

                if p.returncode:
                    raise SyntaxError(stderr.decode('utf-8'))

                if 'binary' in ld_flags:
                    tmp_bin = open(tmp_bin_name, 'rb')
                    result = tmp_bin.read()
                    tmp_bin.close()
                    return result
                else:
                    tmp_bin = ELF(tmp_bin_name)
                    return tmp_bin.get_section_header('.text').content
            finally:
                try:
                    os.unlink(tmp_bin_name)
                except OSError:
                    pass
        finally:
            try:
                os.unlink(tmp_out_name)
            except OSError:
                pass  # pragma: no cover

    else:
        raise NotImplementedError('Unsupported syntax or target platform.')


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

    if not HAVE_CAPSTONE:
        raise NotImplementedError('pwnypack requires capstone to disassemble to AT&T and Intel syntax')

    if target is None:
        target = pwnypack.target.target

    if target.arch == pwnypack.target.Target.Arch.x86:
        if target.bits is pwnypack.target.Target.Bits.bits_32:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        else:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    elif target.arch == pwnypack.target.Target.Arch.arm:
        mode = 0

        if target.bits is pwnypack.target.Target.Bits.bits_32:
            arch = capstone.CS_ARCH_ARM

            if target.mode and pwnypack.target.Target.Mode.arm_thumb:
                mode = capstone.CS_MODE_THUMB
            else:
                mode = capstone.CS_MODE_ARM
                if target.mode and pwnypack.target.Target.Mode.arm_m_class:
                    mode |= capstone.CS_MODE_MCLASS

            if target.mode and pwnypack.target.Target.Mode.arm_v8:
                mode |= capstone.CS_MODE_V8
        else:
            arch = capstone.CS_ARCH_ARM64

        if target.endian is pwnypack.target.Target.Endian.little:
            mode |= capstone.CS_MODE_LITTLE_ENDIAN
        else:
            mode |= capstone.CS_MODE_BIG_ENDIAN

        md = capstone.Cs(arch, mode)
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


def disasm(code, addr=0, syntax=None, target=None):
    """
    Disassemble machine readable code into human readable statements.

    Args:
        code(bytes): The machine code that is to be disassembled.
        addr(int): The memory address of the code (used for relative
            references).
        syntax(AsmSyntax): The output assembler syntax. This defaults to
            nasm on x86 architectures, AT&T on all other architectures.
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

    if syntax is None:
        if target.arch is pwnypack.target.Target.Arch.x86:
            syntax = AsmSyntax.nasm
        else:
            syntax = AsmSyntax.att

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
        default=None,
    )
    parser.add_argument(
        '--address', '-o',
        type=lambda v: int(v, 0),
        default=0,
        help='the address where the code is expected to run',
    )

    args = parser.parse_args(args)
    target = pwnypack.main.target_from_arguments(args)
    if args.syntax is not None:
        syntax = AsmSyntax.__members__[args.syntax]
    else:
        syntax = None
    if args.source is None:
        args.source = sys.stdin.read()
    else:
        args.source = args.source.replace(';', '\n')

    return asm(
        args.source,
        syntax=syntax,
        target=target,
        addr=args.address,
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
        default=None,
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
    if args.syntax is not None:
        syntax = AsmSyntax.__members__[args.syntax]
    else:
        syntax = None

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
        default=None,
    )
    parser.add_argument('file', help='ELF file to extract a symbol from')
    parser.add_argument('symbol', help='the symbol to disassemble')

    args = parser.parse_args(args)
    if args.syntax is not None:
        syntax = AsmSyntax.__members__[args.syntax]
    else:
        syntax = None
    elf = ELF(args.file)
    symbol = elf.get_symbol(args.symbol)
    print('\n'.join(disasm(symbol.content, symbol.value, syntax=syntax, target=elf)))
