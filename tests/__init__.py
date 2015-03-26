import pwny


def setup():
    pwny.target.assume(pwny.Target(arch=pwny.Target.Arch.x86))
