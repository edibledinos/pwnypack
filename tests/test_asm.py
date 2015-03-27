from nose.tools import raises
import pwny


SOURCE_ASM = 'mov al, [0xced]'
RESULT_BIN_32 = b'\xa0\xed\x0c\x00\x00'
RESULT_BIN_64 = b'\x8a\x04%\xed\x0c\x00\x00'


SOURCE_DISASM = b'\x5f'
RESULT_DISASM_32 = ['pop edi']
RESULT_DISASM_64 = ['pop rdi']


target_x86_32 = pwny.Target('x86', 32)
target_x86_64 = pwny.Target('x86', 64)
target_arm_32 = pwny.Target('arm', 32)


def test_asm_with_default_target():
    # Note: set up sets default arch to x86 32bit
    assert pwny.asm(SOURCE_ASM) == RESULT_BIN_32


def test_asm_with_target_x86_32():
    assert pwny.asm(SOURCE_ASM, target=target_x86_32) == RESULT_BIN_32


def test_asm_with_target_x86_64():
    assert pwny.asm(SOURCE_ASM, target=target_x86_64) == RESULT_BIN_64


@raises(SyntaxError)
def test_asm_syntax_error():
    pwny.asm('mov ced, 3')


@raises(NotImplementedError)
def test_asm_unsupported_target():
    pwny.asm(SOURCE_ASM, target=target_arm_32)


def test_disasm_with_default_target():
    # Note: set up sets default arch to x86 32bit
    assert pwny.disasm(SOURCE_DISASM) == RESULT_DISASM_32


def test_disasm_with_target_x86_32():
    assert pwny.disasm(SOURCE_DISASM, target=target_x86_32) == RESULT_DISASM_32


def test_disasm_with_target_x86_64():
    print(RESULT_DISASM_64, pwny.disasm(SOURCE_DISASM, target=target_x86_64))
    assert pwny.disasm(SOURCE_DISASM, target=target_x86_64) == RESULT_DISASM_64


@raises(NotImplementedError)
def test_disasm_unsupported_target():
    pwny.disasm(SOURCE_DISASM, target=target_arm_32)
