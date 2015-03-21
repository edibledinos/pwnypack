import subprocess
import pwnypack.target
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

        if bits is None:
            if target is None:
                target = pwnypack.target.target
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
