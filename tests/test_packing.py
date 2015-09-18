import pytest

import pwny


target_little_endian = pwny.Target(arch=pwny.Target.Arch.unknown, endian=pwny.Target.Endian.little)
target_big_endian = pwny.Target(arch=pwny.Target.Arch.unknown, endian=pwny.Target.Endian.big)


def test_pack():
    assert pwny.pack('I', 0x41424344) == b'DCBA'


def test_pack_format_with_endian():
    assert pwny.pack('>I', 0x41424344) == b'ABCD'


def test_pack_explicit_endian():
    assert pwny.pack('I', 0x41424344, endian=pwny.Target.Endian.big) == b'ABCD'


def test_pack_explicit_target():
    assert pwny.pack('I', 0x41424344, target=target_big_endian) == b'ABCD'


@pytest.mark.xfail(raises=NotImplementedError)
def test_pack_invalid_endian():
    pwny.pack('I', 1, endian='invalid')


def test_unpack():
    assert pwny.unpack('I', b'DCBA') == (0x41424344,)


def test_unpack_format_with_endian():
    assert pwny.unpack('>I', b'ABCD') == (0x41424344,)


def test_unpack_explicit_endian():
    assert pwny.unpack('I', b'ABCD', endian=pwny.Target.Endian.big) == (0x41424344,)


def test_unpack_explicit_target():
    assert pwny.unpack('I', b'ABCD', target=target_big_endian) == (0x41424344,)


@pytest.mark.xfail(raises=NotImplementedError)
def test_unpack_invalid_endian():
    pwny.unpack('I', 'AAAA', endian='invalid')


def test_pack_size():
    # This tests both pack_size in general as well as not padding the byte.
    assert pwny.pack_size('bq') == 9


short_signed_data = [
    [8, -0x7f, b'\x81'],
    [16, -0x7fff, b'\x80\x01'],
    [32, -0x7fffffff, b'\x80\x00\x00\x01'],
    [64, -0x7fffffffffffffff, b'\x80\x00\x00\x00\x00\x00\x00\x01'],
]


short_unsigned_data = [
    [8, 0x61, b'a'],
    [16, 0x6162, b'ab'],
    [32, 0x61626364, b'abcd'],
    [64, 0x6162636465666768, b'abcdefgh'],
]


def test_short_form_pack():
    for width, num, bytestr in short_signed_data:
        f = 'p%d' % width
        yield check_short_form_pack, f, num, bytestr[::-1]
        yield check_short_form_pack_endian, f, num, bytestr[::-1], pwny.Target.Endian.little
        yield check_short_form_pack_endian, f, num, bytestr, pwny.Target.Endian.big

    for width, num, bytestr in short_unsigned_data:
        f = 'P%d' % width
        yield check_short_form_pack, f, num, bytestr[::-1]
        yield check_short_form_pack_endian, f, num, bytestr[::-1], pwny.Target.Endian.little
        yield check_short_form_pack_endian, f, num, bytestr, pwny.Target.Endian.big


def test_short_form_unpack():
    for width, num, bytestr in short_signed_data:
        f = 'u%d' % width
        yield check_short_form_unpack, f, num, bytestr[::-1]
        yield check_short_form_unpack_endian, f, num, bytestr[::-1], pwny.Target.Endian.little
        yield check_short_form_unpack_endian, f, num, bytestr, pwny.Target.Endian.big

    for width, num, bytestr in short_unsigned_data:
        f = 'U%d' % width
        yield check_short_form_unpack, f, num, bytestr[::-1]
        yield check_short_form_unpack_endian, f, num, bytestr[::-1], pwny.Target.Endian.little
        yield check_short_form_unpack_endian, f, num, bytestr, pwny.Target.Endian.big


def test_pointer_pack():
    yield check_short_form_pack, 'p', -66052, b'\xfc\xfd\xfe\xff'
    yield check_short_form_pack_endian, 'p', -66052, b'\xfc\xfd\xfe\xff', pwny.Target.Endian.little
    yield check_short_form_pack_endian, 'p', -66052, b'\xff\xfe\xfd\xfc', pwny.Target.Endian.big

    yield check_short_form_pack, 'P', 4294901244, b'\xfc\xfd\xfe\xff'
    yield check_short_form_pack_endian, 'P', 4294901244, b'\xfc\xfd\xfe\xff', pwny.Target.Endian.little
    yield check_short_form_pack_endian, 'P', 4294901244, b'\xff\xfe\xfd\xfc', pwny.Target.Endian.big


def test_pointer_unpack():
    yield check_short_form_unpack, 'u', -66052, b'\xfc\xfd\xfe\xff'
    yield check_short_form_unpack_endian, 'u', -66052, b'\xfc\xfd\xfe\xff', pwny.Target.Endian.little
    yield check_short_form_unpack_endian, 'u', -66052, b'\xff\xfe\xfd\xfc', pwny.Target.Endian.big

    yield check_short_form_unpack, 'U', 4294901244, b'\xfc\xfd\xfe\xff'
    yield check_short_form_unpack_endian, 'U', 4294901244, b'\xfc\xfd\xfe\xff', pwny.Target.Endian.little
    yield check_short_form_unpack_endian, 'U', 4294901244, b'\xff\xfe\xfd\xfc', pwny.Target.Endian.big


def check_short_form_pack(f, num, bytestr):
    assert getattr(pwny, f)(num) == bytestr


def check_short_form_pack_endian(f, num, bytestr, endian):
    assert getattr(pwny, f)(num, endian=endian) == bytestr


def check_short_form_unpack(f, num, bytestr):
    assert getattr(pwny, f)(bytestr) == num


def check_short_form_unpack_endian(f, num, bytestr, endian):
    assert getattr(pwny, f)(bytestr, endian=endian) == num
