import six
import mock
import pytest

import pwny


headers = [
    {
        'data': b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00\x01\x00\x00\x00@\x04@\x00\x00'
                b'\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00p\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00\t'
                b'\x00@\x00\x1e\x00\x1b\x00',
        'header': {
            'arch': pwny.Target.Arch.x86,
            'bits': 64,
            'endian': pwny.Target.Endian.little,
            'abi_version': 0,
            'entry': 4195392,
            'flags': 0,
            'hsize': 64,
            'osabi': pwny.ELF.OSABI.system_v,
            'phentsize': 56,
            'phnum': 9,
            'phoff': 64,
            'shentsize': 64,
            'shnum': 30,
            'shoff': 4464,
            'shstrndx': 27,
            'type': pwny.ELF.Type.executable
        },
    },
    {
        'data': b'\x7fELF\x02\x01\x01\x03\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00\x01\x00\x00\x00N\x0f@\x00\x00'
                b'\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\xa8\x1d\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x008\x00'
                b'\x06\x00@\x00\x1f\x00\x1c\x00',
        'header': {
            'arch': pwny.Target.Arch.x86,
            'bits': 64,
            'endian': pwny.Target.Endian.little,
            'abi_version': 0,
            'entry': 4198222,
            'flags': 0,
            'hsize': 64,
            'osabi': pwny.ELF.OSABI.linux,
            'phentsize': 56,
            'phnum': 6,
            'phoff': 64,
            'shentsize': 64,
            'shnum': 31,
            'shoff': 794024,
            'shstrndx': 28,
            'type': pwny.ELF.Type.executable,
        },
    },
    {
        'data': b'\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x03\x00\x01\x00\x00\x00 \x83\x04\x08'
                b'4\x00\x00\x00L\x11\x00\x00\x00\x00\x00\x004\x00 \x00\t\x00(\x00\x1e\x00\x1b\x00\x06\x00\x00\x004\x00'
                b'\x00\x004\x80\x04\x08',
        'header': {
            'arch':pwny.Target.Arch.x86,
            'bits': 32,
            'endian': pwny.Target.Endian.little,
            'abi_version': 0,
            'entry': 134513440,
            'flags': 0,
            'hsize': 52,
            'osabi': pwny.ELF.OSABI.system_v,
            'phentsize': 32,
            'phnum': 9,
            'phoff': 52,
            'shentsize': 40,
            'shnum': 30,
            'shoff': 4428,
            'shstrndx': 27,
            'type': pwny.ELF.Type.executable,
        },
    },
    {
        'data': b'\x7fELF\x01\x01\x01\x03\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x03\x00\x01\x00\x00\x00\n\x8d\x04\x08'
                b'4\x00\x00\x00\xf0 \n\x00\x00\x00\x00\x004\x00 \x00\x06\x00(\x00\x1f\x00\x1c\x00\x01\x00\x00\x00\x00'
                b'\x00\x00\x00\x00\x80\x04\x08',
        'header': {
            'arch': pwny.Target.Arch.x86,
            'bits': 32,
            'endian': pwny.Target.Endian.little,
            'abi_version': 0,
            'entry': 134515978,
            'flags': 0,
            'hsize': 52,
            'osabi': pwny.ELF.OSABI.linux,
            'phentsize': 32,
            'phnum': 6,
            'phoff': 52,
            'sections': [],
            'shentsize': 40,
            'shnum': 31,
            'shoff': 663792,
            'shstrndx': 28,
            'strings': None,
            'type': pwny.ELF.Type.executable,
        },
    }
]


@pytest.mark.parametrize('header', headers)
def test_elf_header_parse(header):
    data, values = header['data'], header['header']
    elf = pwny.ELF()
    elf._parse_header(data)
    for key, value in values.items():
        assert getattr(elf, key, value) == value, '%s != %r (%r)' % (key, value, getattr(elf, key))


def test_elf_parse_section_invalid_type():
    section_fmt = 'IIIIIIIIII'
    section_fmt_size = pwny.pack_size(section_fmt)
    section = pwny.pack(
        section_fmt,
        1,
        0x5fffffff,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        section_fmt_size,
    )
    elf = pwny.ELF()
    elf.bits = 32
    section = elf.SectionHeader(elf, section)
    assert section.type == pwny.ELF.SectionHeader.Type.unknown


def test_elf_parse_file_32():
    b = six.BytesIO()

    header_fmt = '4sBBBBB7sHHIIIIIHHHHHH'
    header_fmt_size = pwny.pack_size(header_fmt)

    section_fmt = 'IIIIIIIIII'
    section_fmt_size = pwny.pack_size(section_fmt)

    strings_section = b'\x00strings\x00'

    b.write(pwny.pack(
        header_fmt,
        b'\x7fELF',
        1,
        1,
        1,
        pwny.ELF.OSABI.linux.value,
        0,
        b'\x00' * 7,
        pwny.ELF.Type.executable.value,
        pwny.ELF.Machine.i386.value,
        1,
        0,
        0,
        header_fmt_size,
        0,
        header_fmt_size,
        0,
        0,
        section_fmt_size,
        1,
        0,
    ))

    b.write(pwny.pack(
        section_fmt,
        1,
        pwny.ELF.SectionHeader.Type.null.value,
        0,
        0,
        header_fmt_size + section_fmt_size,
        len(strings_section),
        0,
        0,
        0,
        section_fmt_size,
    ))

    b.write(strings_section)
    b.seek(0)

    elf = pwny.ELF(b)

    for key, value in {
        'arch': pwny.Target.Arch.x86,
        'bits': 32,
        'endian': pwny.Target.Endian.little,
        'abi_version': 0,
        'entry': 0,
        'flags': 0,
        'hsize': header_fmt_size,
        'osabi': pwny.ELF.OSABI.linux,
        'phentsize': 0,
        'phnum': 0,
        'phoff': 0,
        'shentsize': section_fmt_size,
        'shnum': 1,
        'shoff': header_fmt_size,
        'shstrndx': 0,
        'type': pwny.ELF.Type.executable,
    }.items():
        assert getattr(elf, key) == value, '%s != %r (%r)' % (key, value, getattr(elf, key))

    assert len(elf.section_headers) == 1


def test_elf_parse_file_64():
    b = six.BytesIO()

    header_fmt = '4sBBBBB7sHHIQQQIHHHHHH'
    header_fmt_size = pwny.pack_size(header_fmt)

    section_fmt = 'IIQQQQIIQQ'
    section_fmt_size = pwny.pack_size(section_fmt)

    strings_section = b'\x00strings\x00'

    b.write(pwny.pack(
        header_fmt,
        b'\x7fELF',
        2,
        1,
        1,
        pwny.ELF.OSABI.linux.value,
        0,
        b'\x00' * 7,
        pwny.ELF.Type.executable.value,
        pwny.ELF.Machine.x86_64.value,
        1,
        0,
        0,
        header_fmt_size,
        0,
        header_fmt_size,
        0,
        0,
        section_fmt_size,
        1,
        0,
    ))

    b.write(pwny.pack(
        section_fmt,
        1,
        pwny.ELF.SectionHeader.Type.null.value,
        0,
        0,
        header_fmt_size + section_fmt_size,
        len(strings_section),
        0,
        0,
        0,
        section_fmt_size,
    ))

    b.write(strings_section)
    b.seek(0)

    elf = pwny.ELF(b)

    for key, value in {
        'arch': pwny.Target.Arch.x86,
        'bits': 64,
        'endian': pwny.Target.Endian.little,
        'abi_version': 0,
        'entry': 0,
        'flags': 0,
        'hsize': header_fmt_size,
        'osabi': pwny.ELF.OSABI.linux,
        'phentsize': 0,
        'phnum': 0,
        'phoff': 0,
        'shentsize': section_fmt_size,
        'shnum': 1,
        'shoff': header_fmt_size,
        'shstrndx': 0,
        'type': pwny.ELF.Type.executable,
    }.items():
        assert getattr(elf, key) == value, '%s != %r' % (key, value)

    assert len(elf.section_headers) == 1


def test_elf_parse_file_open():
    b = six.BytesIO()

    header_fmt = '4sBBBBB7sHHIIIIIHHHHHH'
    header_fmt_size = pwny.pack_size(header_fmt)

    b.write(pwny.pack(
        header_fmt,
        b'\x7fELF',
        1,
        1,
        1,
        pwny.ELF.OSABI.linux.value,
        0,
        b'\x00' * 7,
        pwny.ELF.Type.executable.value,
        pwny.ELF.Machine.i386.value,
        1,
        0,
        0,
        header_fmt_size,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ))

    b.seek(0)

    with mock.patch('pwnypack.elf.open', create=True) as mock_open:
        mock_open.return_value = b
        pwny.ELF('test.elf')
