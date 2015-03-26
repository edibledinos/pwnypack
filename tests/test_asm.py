from nose.tools import raises
import pwny


SOURCE = 'mov al, [0xced]'
RESULT_BIN_32 = b'\xa0\xed\x0c\x00\x00'
RESULT_BIN_64 = b'\x8a\x04%\xed\x0c\x00\x00'
RESULT_ITH_32 = b':05000000A0ED0C000062\n:00000001FF\n'
RESULT_ITH_64 = b':070000008A0425ED0C00004D\n:00000001FF\n'


target_x86_32 = pwny.Target('x86', 32)
target_x86_64 = pwny.Target('x86', 64)


def test_asm_with_default_target():
    if pwny.target.arch != 'x86':
        # Test only supported on x86.
        return

    if pwny.target.bits == 32:
        assert pwny.asm(SOURCE) == RESULT_BIN_32
    else:
        assert pwny.asm(SOURCE) == RESULT_BIN_64


def test_asm_with_target_x86_32():
    assert pwny.asm(SOURCE, target=target_x86_32) == RESULT_BIN_32

def test_asm_with_target_x86_64():
    assert pwny.asm(SOURCE, target=target_x86_64) == RESULT_BIN_64


def test_asm_with_format_x86_32():
    assert pwny.asm(SOURCE, fmt=pwny.asm.Format.ith, target=target_x86_32) == RESULT_ITH_32


def test_asm_with_format_x86_64():
    assert pwny.asm(SOURCE, fmt=pwny.asm.Format.ith, target=target_x86_64) == RESULT_ITH_64


@raises(ValueError)
def test_asm_invalid_format():
    pwny.asm(SOURCE, fmt='ced')


@raises(SyntaxError)
def test_asm_syntax_error():
    pwny.asm('mov ced, 3')
