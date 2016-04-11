import functools
from enum import IntEnum

try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict
import six

import pwnypack.asm
from pwnypack.shellcode.ops import SyscallInvoke, LoadRegister
from pwnypack.shellcode.translate import translate
from pwnypack.shellcode.types import Register, Offset, Buffer


__all__ = ['BaseEnvironment']


class BaseEnvironment(object):
    """
    The abstract base for all shellcode environments.
    """

    class TranslateOutput(IntEnum):
        """
        Output format the translate function.
        """

        code = 0  #: Emit binary, executable code.
        assembly = 1  #: Emit assembly source.
        meta = 2  #: Emit the declarative version of the translated function.

    def __init__(self):
        self.data = OrderedDict()
        self.buffers = []

    @property
    def target(self):
        raise NotImplementedError('Target does not define a target architecture')

    def _alloc_data(self, bytes):
        offset, _ = self.data.get(bytes, (None, None))
        if offset is not None:
            return offset

        offset = Offset(sum(len(b) for b in six.iterkeys(self.data))) if self.data else Offset(0)
        self.data[bytes] = (offset, bytes)
        return offset

    def alloc_data(self, value):
        """
        Allocate a piece of data that will be included in the shellcode body.

        Arguments:
            value(...): The value to add to the shellcode. Can be bytes or
                string type.

        Returns:
            ~pwnypack.types.Offset: The offset used to address the data.
        """

        if isinstance(value, six.binary_type):
            return self._alloc_data(value)
        elif isinstance(value, six.text_type):
            return self._alloc_data(value.encode('utf-8') + b'\0')
        else:
            raise TypeError('No idea how to encode %s' % repr(value))

    def alloc_buffer(self, length):
        """
        Allocate a buffer (a range of uninitialized memory).

        Arguments:
            length(int): The length of the buffer to allocate.

        Returns:
            ~pwnypack.types.Buffer: The object used to address this buffer.
        """

        buf = Buffer(sum(len(v) for v in six.iterkeys(self.data)) + sum(v.length for v in self.buffers), length)
        self.buffers.append(buf)
        return buf

    def reg_push(self, reg):
        raise NotImplementedError('Target does not define reg_push')

    def reg_load_imm(self, reg, value):
        raise NotImplementedError('Target does not define reg_load_imm')

    def reg_load_reg(self, reg1, reg2):
        raise NotImplementedError('Target does not define reg_load_reg')

    def reg_load_offset(self, reg, offset):
        raise NotImplementedError('Target does not define reg_load_offset')

    def reg_load_array(self, reg, value):
        raise NotImplementedError('Target does not define reg_load_array')

    def reg_load(self, reg, value):
        if isinstance(value, (six.text_type, six.binary_type)):
            value = self.alloc_data(value)

        if value is None:
            return self.reg_load_imm(reg, 0)

        elif isinstance(value, Register):
            return self.reg_load_reg(reg, value)

        elif isinstance(value, Offset):
            return self.reg_load_offset(reg, value)

        elif isinstance(value, Buffer):
            return self.reg_load_offset(reg, sum(len(v) for v in six.iterkeys(self.data)) + value.offset)

        elif isinstance(value, int):
            return self.reg_load_imm(reg, value)

        elif isinstance(value, (list, tuple)):
            return self.reg_load_array(reg, value)

        elif isinstance(value, SyscallInvoke):
            syscall_code, syscall_reg = self.syscall(value)
            return syscall_code + self.reg_load(reg, syscall_reg)

        else:
            raise TypeError('Invalid argument type "%s"' % repr(value))

    def syscall(self, op):
        raise NotImplementedError('Target does not define syscall method')

    def finalize(self, code, data):
        raise NotImplementedError('Target does not define finalize method')

    def compile(self, ops):
        """
        Translate a list of operations into its assembler source.

        Arguments:
            ops(list): A list of shellcode operations.

        Returns:
            str: The assembler source code that implements the shellcode.
        """

        def _compile():
            code = []

            for op in ops:
                if isinstance(op, SyscallInvoke):
                    code.extend(self.syscall(op)[0])
                elif isinstance(op, LoadRegister):
                    code.extend(self.reg_load(op.register, op.value))
                elif isinstance(op, str):
                    code.extend(op.split('\n'))
                else:
                    raise ValueError('No idea how to assemble "%s"' % repr(op))
            return code

        # We do 2 passes to make sure all data is allocated so buffers point at the right offset.
        _compile()
        return '\n'.join(self.finalize(_compile(), self.data))

    def assemble(self, ops):
        """
        Assemble a list of operations into executable code.

        Arguments:
            ops(list): A list of shellcode operations.

        Returns:
            bytes: The executable code that implements the shellcode.
        """

        return pwnypack.asm.asm(self.compile(ops), target=self.target)

    @classmethod
    def translate(cls, output=TranslateOutput.code):
        """
        Decorator that turns a function into a shellcode emitting function.

        Arguments:
            output(~pwnypack.shellcode.base.BaseEnvironment.TranslateOutput): The output
                format the shellcode function will produce.

        Returns:
            A decorator that will translate the given function into a
            shellcode generator
        """

        def decorator(f):
            @functools.wraps(f)
            def proxy(*args, **kwargs):
                env = cls()
                result = translate(env, f, *args, **kwargs)
                if output == cls.TranslateOutput.code:
                    return env.assemble(result)
                elif output == cls.TranslateOutput.assembly:
                    return env.target, env.compile(result)
                else:
                    return env, result
            return proxy
        return decorator
