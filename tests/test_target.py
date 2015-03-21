import mock
from nose.tools import raises
import pwny


def test_default_arch_32bit():
    with mock.patch('platform.architecture') as platform_mock:
        platform_mock.return_value = ('32bit',)
        assert pwny.Target().arch is pwny.Architecture.x86


def test_default_arch_64bit():
    with mock.patch('platform.architecture') as platform_mock:
        platform_mock.return_value = ('64bit',)
        assert pwny.Target().arch is pwny.Architecture.x86_64


def test_set_arch():
    with mock.patch('platform.architecture') as platform_mock:
        platform_mock.return_value = ('64bit',)
        target = pwny.Target(arch=pwny.Architecture.x86)
        assert target.arch is pwny.Architecture.x86


def test_default_endianness():
    assert pwny.Target().endian is pwny.Endianness.little


def test_set_endianness():
    target = pwny.Target(endian=pwny.Endianness.big)
    assert target.endian is pwny.Endianness.big


def test_default_bits_x86():
    target = pwny.Target(arch=pwny.Architecture.x86)
    assert target.bits == 32


def test_default_bits_x86_64():
    target = pwny.Target(arch=pwny.Architecture.x86_64)
    assert target.bits == 64


@raises(NotImplementedError)
def test_default_bits_unsupported():
    target = pwny.Target(arch=pwny.Architecture.aarch64)
    _ = target.bits


def test_set_bits():
    target = pwny.Target(bits=33)
    assert target.bits == 33


def test_target_assume():
    target = pwny.Target()
    target.assume(pwny.Target(arch=pwny.Architecture.aarch64, bits=33, endian=pwny.Endianness.little))
    assert target.arch is pwny.Architecture.aarch64 and target.bits == 33 and target.endian == pwny.Endianness.little
