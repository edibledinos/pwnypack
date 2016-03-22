__all__ = ['LoadRegister']


class LoadRegister(object):
    def __init__(self, register, value):
        self.register = register
        self.value = value

    def __repr__(self):
        return 'LoadRegister(%r, %r)' % (self.register, self.value)


class SyscallInvoke(object):
    def __init__(self, syscall_def, args):
        self.syscall_def = syscall_def
        self.args = args

    def __repr__(self):
        return '%s(%s)' % (self.syscall_def.name, ', '.join(repr(a) for a in self.args))
