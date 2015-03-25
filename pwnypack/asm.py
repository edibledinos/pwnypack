from __future__ import print_function
import argparse
import subprocess
import sys
import capstone
import pwnypack.target
import pwnypack.main
import pwnypack.codec
import tempfile
import os
from enum import Enum


__all__ = [
    'asm',
]


class Asm(object):
    class Format(Enum):
        bin = 'bin'
        ith = 'ith'
        srec = 'srec'
        aout = 'aout'
        aoutb = 'aoutb'
        coff = 'coff'
        elf32 = 'elf32'
        elf64 = 'elf64'
        elfx32 = 'elfx32'
        as86 = 'as86'
        obj = 'obj'
        win32 = 'win32'
        win64 = 'win64'
        rdf = 'rdf'
        ieee = 'ieee'
        macho32 = 'macho32'
        macho64 = 'macho64'
        dbg = 'dbg'

    @classmethod
    def __call__(cls, code, fmt=Format.bin, bits=None, target=None):
        if not isinstance(fmt, cls.Format):
            fmt = cls.Format(fmt)

        if target is None:
            target = pwnypack.target.target

        assert target.arch in (pwnypack.target.Architecture.x86, pwnypack.target.Architecture.x86_64)

        if bits is None:
            bits = target.bits

        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(('bits %d\n%s' % (bits, code)).encode('utf-8'))
        tmp.close()

        try:
            p = subprocess.Popen(
                [
                    'nasm',
                    '-o',
                    '/dev/stdout',
                    '-f',
                    fmt.value,
                    tmp.name,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = p.communicate()
            if p.returncode:
                raise SyntaxError(stderr.decode('utf-8'))
            return stdout
        finally:
            os.unlink(tmp.name)

asm = Asm()


def disasm(code, addr, target=None):
    if target is None:
        target = pwnypack.target.target

    if target.arch == pwnypack.target.Architecture.x86:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    elif target.arch == pwnypack.target.Architecture.x86_64:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        raise NotImplementedError('Only x86 and x86_64 architectures are currently supported')

    statements = []
    total_size = 0
    for (_, size, mnemonic, op_str) in md.disasm_lite(code, addr):
        statements.append((mnemonic + ' ' + op_str).strip())
        total_size += size

    if total_size != len(code):
        raise SyntaxError('Failed to disassemble.')

    return statements


@pwnypack.main.register('asm')
def asm_app(parser, cmd, args):  # pragma: no cover
    """
    Assemble code from commandline or stdin.

    Please not that all semi-colons are replaced with carriage returns
    unless source is read from stdin.
    """

    parser.add_argument('source', help='the code to assemble, read from stdin if omitted', nargs='?')
    parser.add_argument(
        '--arch', '-a',
        choices=['x86', 'x86_64'],
        default=pwnypack.target.target.arch.name,
        help='the target architecture',
    )
    parser.add_argument(
        '--output-format', '-F',
        choices=asm.Format.__members__.keys(),
        default=asm.Format.bin.name,
        help='the output format',
    )
    args = parser.parse_args(args)

    target = pwnypack.target.Target(arch=pwnypack.target.Architecture.__members__[args.arch])
    fmt = asm.Format(asm.Format.__members__[args.output_format])

    if args.source is None:
        args.source = sys.stdin.read()
    else:
        args.source = args.source.replace(';', '\n')

    return asm(
        args.source,
        fmt=fmt,
        target=target,
    )


@pwnypack.main.register('disasm')
def asm_app(_parser, cmd, args):  # pragma: no cover
    """
    Disassemble code from commandline or stdin.
    """

    parser = argparse.ArgumentParser(
        prog=_parser.prog,
        description=_parser.description,
    )
    parser.add_argument('code', help='the code to disassemble, read from stdin if omitted', nargs='?')
    parser.add_argument(
        '--arch', '-a',
        choices=['x86', 'x86_64'],
        default=pwnypack.target.target.arch.name,
        help='the target architecture',
    )
    parser.add_argument(
        '--address', '-b',
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

    target = pwnypack.target.Target(arch=pwnypack.target.Architecture.__members__[args.arch])

    if args.format is None:
        if args.code is None:
            args.format = 'bin'
        else:
            args.format = 'hex'

    if args.format == 'hex':
        code = pwnypack.codec.dehex(pwnypack.main.string_value_or_stdin(args.code))
    else:
        code = pwnypack.main.binary_value_or_stdin(args.code)

    try:
        statements = disasm(code, args.address, target=target)
    except SyntaxError:
        print('Failed to disassemble.', file=sys.stderr)
        sys.exit(1)

    print('\n'.join(statements))
