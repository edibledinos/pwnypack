import pytest

import pwny


target_x86_32 = pwny.Target('x86', 32)
target_x86_64 = pwny.Target('x86', 64)
target_arm_32_le = pwny.Target('arm', 32, pwny.Target.Endian.little)
target_arm_32_be = pwny.Target('arm', 32, pwny.Target.Endian.big)
target_armv7m_32_le = pwny.Target('arm', 32, pwny.Target.Endian.little, mode=pwny.Target.Mode.arm_m_class)
target_armv7m_32_be = pwny.Target('arm', 32, pwny.Target.Endian.big, mode=pwny.Target.Mode.arm_m_class)
target_arm_64_le = pwny.Target('arm', 64, pwny.Target.Endian.little)
target_arm_64_be = pwny.Target('arm', 64, pwny.Target.Endian.big)
target_unknown_32 = pwny.Target('unknown', 32, pwny.Target.Endian.little)


ASM_TESTS = [
    # Note: set up sets default arch to x86 32bit
    (None, pwny.AsmSyntax.nasm, 'mov al,[0xced]', b'\xa0\xed\x0c\x00\x00'),
    (target_x86_32, None, 'mov al,[0xced]', b'\xa0\xed\x0c\x00\x00'),
    (target_x86_32, pwny.AsmSyntax.nasm, 'mov al,[0xced]', b'\xa0\xed\x0c\x00\x00'),
    (target_x86_32, pwny.AsmSyntax.att, 'movb 0xced, %al', b'\xa0\xed\x0c\x00\x00'),
    (target_x86_32, pwny.AsmSyntax.intel, 'mov al, byte ptr [0xced]', b'\xa0\xed\x0c\x00\x00'),

    (target_x86_64, None, 'mov al,[0xced]', b'\x8a\x04%\xed\x0c\x00\x00'),
    (target_x86_64, pwny.AsmSyntax.nasm, 'mov al,[0xced]', b'\x8a\x04%\xed\x0c\x00\x00'),
    (target_x86_64, pwny.AsmSyntax.att, 'movb 0xced, %al', b'\x8a\x04%\xed\x0c\x00\x00'),
    (target_x86_64, pwny.AsmSyntax.intel, 'mov al, byte ptr [0xced]', b'\x8a\x04%\xed\x0c\x00\x00'),

    (target_arm_32_le, None, 'add r0, r1, #0', b'\x00\x00\x81\xe2'),
    (target_arm_32_be, None, 'add r0, r1, #0', b'\xe2\x81\x00\x00'),
    (target_armv7m_32_le, None, 'push {r0}', b'\x01\xb4'),
    (target_armv7m_32_be, None, 'push {r0}', b'\xb4\x01'),

    (target_arm_64_le, None, 'add x0, x1, #0', b' \x00\x00\x91'),
    # The output of as/ld and capstone disagree. Assume a failure will happen.
    pytest.mark.xfail()((target_arm_64_be, None, 'add x0, x1, #0', b'\x91\x00\x00 ')),
]


@pytest.mark.parametrize(('test_target', 'syntax', 'source', 'result'), ASM_TESTS)
def test_asm(test_target, syntax, source, result, target):
    try:
        output = pwny.asm(source, syntax=syntax, target=test_target)
    except RuntimeError:
        # Toolchain wasn't found. Unfortunate, but unavoidable on travis-ci atm.
        pytest.skip('No suitable binutils was found for %s' % target)
    assert output == result, 'Got %r, expected %r' % (output, result)


@pytest.mark.xfail(raises=SyntaxError)
def test_asm_syntax_error():
    pwny.asm('mov ced, 3', target=target_x86_32)


@pytest.mark.xfail(raises=NotImplementedError)
def test_asm_unsupported_target():
    pwny.asm('mov al, [0xced]', target=target_unknown_32)


@pytest.mark.parametrize(('test_target', 'syntax', 'result', 'source'), ASM_TESTS)
def test_disasm(test_target, syntax, source, result, target):
    output = pwny.disasm(source, syntax=syntax, target=test_target)
    assert output == [result], 'Got %r, expected %r' % (output, result)


@pytest.mark.xfail(raises=NotImplementedError)
def test_disasm_unsupported_target():
    pwny.disasm(b'\x5f', target=target_unknown_32)
