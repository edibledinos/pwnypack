from nose.tools import raises
import pwny


SOURCE = 'mov al, [0xced]'
RESULT_BIN_32 = b'\xa0\xed\x0c\x00\x00'
RESULT_BIN_64 = b'\x8a\x04%\xed\x0c\x00\x00'
RESULT_ITH_32 = b':05000000A0ED0C000062\n:00000001FF\n'
RESULT_ITH_64 = b':070000008A0425ED0C00004D\n:00000001FF\n'


def test_asm():
    if pwny.target.bits == 32:
        assert pwny.asm(SOURCE) == RESULT_BIN_32
    else:
        assert pwny.asm(SOURCE) == RESULT_BIN_64


def test_asm_with_bits():
    assert pwny.asm(SOURCE, bits=32) == RESULT_BIN_32
    assert pwny.asm(SOURCE, bits=64) == RESULT_BIN_64


def test_asm_with_target():
    target_32 = pwny.Target(arch=pwny.Architecture.x86)
    target_64 = pwny.Target(arch=pwny.Architecture.x86_64)
    assert pwny.asm(SOURCE, target=target_32) == RESULT_BIN_32
    assert pwny.asm(SOURCE, target=target_64) == RESULT_BIN_64


def test_asm_with_bits_and_target():
    target_32 = pwny.Target(arch=pwny.Architecture.x86)
    target_64 = pwny.Target(arch=pwny.Architecture.x86_64)
    assert pwny.asm(SOURCE, bits=32, target=target_64) == RESULT_BIN_32
    assert pwny.asm(SOURCE, bits=64, target=target_32) == RESULT_BIN_64


def test_asm_with_format():
    assert pwny.asm(SOURCE, fmt=pwny.asm.Format.ith, bits=32) == RESULT_ITH_32
    assert pwny.asm(SOURCE, fmt=pwny.asm.Format.ith, bits=64) == RESULT_ITH_64


@raises(ValueError)
def test_asm_invalid_format():
    pwny.asm(SOURCE, fmt='ced')


@raises(SyntaxError)
def test_asm_syntax_error():
    pwny.asm('mov ced, 3')
