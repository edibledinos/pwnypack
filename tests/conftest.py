import pytest
import pwny


@pytest.fixture(autouse=True)
def target():
    pwny.target.assume(pwny.Target(arch=pwny.Target.Arch.x86, bits=pwny.Target.Bits.bits_32))
