import pytest
import sys

from pwny import *


@pytest.mark.xfail(sys.version_info < (2, 7),
                   reason="inspect.getcallargs new in python 2.7")
def test_shellcode_translate():
    @sc.LinuxX86Mutable.translate()
    def shellcode():
        buf = alloc_buffer(64)
        sys_read(0, buf, buf.length)
        sys_write(1, buf, buf.length)
        sys_setresuid(sys_geteuid(), sys_geteuid(), sys_geteuid())
        sys_execve(u'/bin/sh', [u'/bin/sh', u'-c', buf, None], None)
    shellcode()


SHELLCODE_ENVS = [
    (sc.LinuxX86Mutable, ()),
    (sc.LinuxX86MutableNullSafe, ()),
    (sc.LinuxX86_64Mutable, ()),
    (sc.LinuxX86_64MutableNullSafe, ()),

    (sc.LinuxARM, ()),
    (sc.LinuxARM, (Target.Endian.little,)),
    (sc.LinuxARM, (Target.Endian.big,)),

    (sc.LinuxARMThumb, ()),
    (sc.LinuxARMThumb, (Target.Endian.little,)),
    (sc.LinuxARMThumb, (Target.Endian.big,)),

    (sc.LinuxARMThumbMixed, ()),
    (sc.LinuxARMThumbMixed, (Target.Endian.little,)),
    (sc.LinuxARMThumbMixed, (Target.Endian.big,)),

    (sc.LinuxAArch64, ()),
    (sc.LinuxAArch64, (Target.Endian.little,)),
    (sc.LinuxAArch64, (Target.Endian.big,)),
]


@pytest.mark.parametrize(('env_type', 'env_args'), SHELLCODE_ENVS)
def test_shellcode_env_simple(env_type, env_args):
    env = env_type(*env_args)
    env.compile([
        env.sys_exit(0),
    ])


@pytest.mark.parametrize(('env_type', 'env_args'), SHELLCODE_ENVS)
def test_shellcode_env_complex(env_type, env_args):
    env = env_type(*env_args)
    buf = env.alloc_buffer(64)
    env.compile([
        sc.LoadRegister(env.SYSCALL_REG, 0xdeadcafe),
        env.sys_read(0, buf, buf.length - 1),
        env.sys_write(1, buf, buf.length - 1),
        env.sys_setresuid(env.sys_geteuid(), env.sys_geteuid(), env.sys_geteuid()),
        env.sys_execve(u'/bin/sh', [u'/bin/sh', u'-c', buf, None], None),
    ])


@pytest.mark.parametrize(('env_type', 'env_args'), SHELLCODE_ENVS)
@pytest.mark.xfail(raises=RuntimeError,
                   reason='proper binutils missing on CI system')
def test_shellcode_env_complex(env_type, env_args):
    env = env_type(*env_args)
    buf = env.alloc_buffer(64)
    env.compile([
        sc.LoadRegister(env.SYSCALL_REG, 0xdeadcafe),
        env.sys_read(0, buf, buf.length - 1),
        env.sys_write(1, buf, buf.length - 1),
        env.sys_setresuid(env.sys_geteuid(), env.sys_geteuid(), env.sys_geteuid()),
        env.sys_execve(u'/bin/sh', [u'/bin/sh', u'-c', buf, None], None),
    ])
