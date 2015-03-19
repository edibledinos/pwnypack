import subprocess
import pwnypack.target
import tempfile


__all__ = [
    'asm',
]


def asm(code, format='bin', bits=None, target=None):
    if bits is None:
        if target is None:
            target = pwnypack.target.target
        bits = target.bits

    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write('bits %d\n' % bits)
    tmp.write(code)
    tmp.close()

    try:
        p = subprocess.Popen(
            [
                'nasm',
                '-o',
                '/dev/stdout',
                '-f',
                format,
                tmp.name,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = p.communicate(code)
        if p.returncode:
            raise SyntaxError(stderr)
        return stdout
    finally:
        tmp.unlink(tmp.name)
