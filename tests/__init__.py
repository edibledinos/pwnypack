import pwny


def setup():
    pwny.target.assume(pwny.Target(arch=pwny.Architecture.x86))
