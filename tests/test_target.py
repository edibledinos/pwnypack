import mock
import pytest

import pwny


def test_default_arch_x86():
    with mock.patch('platform.machine') as platform_mock:
        platform_mock.return_value = 'i386'
        assert pwny.Target().arch is pwny.Target.Arch.x86


def test_default_arch_x86_64():
    with mock.patch('platform.machine') as platform_mock:
        platform_mock.return_value = 'x86_64'
        assert pwny.Target().arch is pwny.Target.Arch.x86


def test_default_arch_unknown():
    with mock.patch('platform.machine') as platform_mock:
        platform_mock.return_value = 'unknown'
        assert pwny.Target().arch is pwny.Target.Arch.unknown


def test_default_arch_32bit():
    with mock.patch('platform.architecture') as platform_mock:
        platform_mock.return_value = ('32bit',)
        assert pwny.Target().bits is pwny.Target.Bits.bits_32


def test_default_arch_64bit():
    with mock.patch('platform.architecture') as platform_mock:
        platform_mock.return_value = ('64bit',)
        assert pwny.Target().bits is pwny.Target.Bits.bits_64


def test_set_arch():
    with mock.patch('platform.architecture') as platform_mock:
        platform_mock.return_value = ('64bit',)
        target = pwny.Target(arch=pwny.Target.Arch.x86)
        assert target.arch is pwny.Target.Arch.x86


def test_default_endian():
    assert pwny.Target().endian is pwny.Target.Endian.little


def test_set_endian():
    target = pwny.Target(arch=pwny.Target.Arch.unknown, endian=pwny.Target.Endian.big)
    assert target.endian is pwny.Target.Endian.big


def test_default_bits_x86():
    target = pwny.Target(arch=pwny.Target.Arch.x86)
    assert target.bits == 32


@pytest.mark.xfail(raises=NotImplementedError)
def test_default_bits_unsupported():
    target = pwny.Target(arch=pwny.Target.Arch.unknown)
    _ = target.bits


def test_set__bits():
    target = pwny.Target(arch=pwny.Target.Arch.x86, bits=64)
    assert target.bits == 64


@pytest.mark.xfail(raises=ValueError)
def test_set_invalid_bits():
    pwny.Target(bits=33)


def test_target_assume():
    target = pwny.Target()
    target.assume(pwny.Target(arch=pwny.Target.Arch.arm, endian=pwny.Target.Endian.little, bits=64, mode=2))
    assert target.arch is pwny.Target.Arch.arm and \
           target.endian == pwny.Target.Endian.little and \
           target.bits == 64 and \
           target.mode == 2
