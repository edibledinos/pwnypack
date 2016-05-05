try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict
from enum import IntEnum
import functools

from kwonly_args import first_kwonly_arg
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

    @property
    def PREAMBLE(self):
        raise NotImplementedError('Target does not define a preamble')

    @property
    def REGISTER_WIDTH_MAP(self):
        raise NotImplementedError('Target does not define a register width map')

    REGISTER_WIDTH = None  #: Mapping of register -> width, filled by __init__ based on REGISTER_WIDTH_MAP

    @property
    def STACK_REG(self):
        raise NotImplementedError('Target does not define a stack register')

    @property
    def OFFSET_REG(self):
        raise NotImplementedError('Target does not define an offset register')

    @property
    def TEMP_REG(self):
        raise NotImplementedError('Target does not define a temporary register mapping')

    @property
    def SYSCALL_RET_REG(self):
        raise NotImplementedError('Target does not define a syscall return register')

    def __init__(self):
        if self.REGISTER_WIDTH is None:
            self.REGISTER_WIDTH = dict([
                (reg_, width)
                for (width, regs) in self.REGISTER_WIDTH_MAP.items()
                for reg_ in regs
            ])
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

    def reg_pop(self, reg):
        raise NotImplementedError('Target does not define reg_pop')

    def reg_add_imm(self, reg, imm):
        raise NotImplementedError('Target does not define reg_add_imm')

    def reg_sub_imm(self, reg, imm):
        raise NotImplementedError('Target does not define reg_sub_imm')

    def reg_add_reg(self, reg1, reg2):
        raise NotImplementedError('Target does not define reg_add_reg')

    def reg_sub_reg(self, reg1, reg2):
        raise NotImplementedError('Target does not define reg_add_reg')

    def reg_load_imm(self, reg, value):
        raise NotImplementedError('Target does not define reg_load_imm')

    def reg_load_reg(self, reg1, reg2):
        raise NotImplementedError('Target does not define reg_load_reg')

    def reg_load_offset(self, reg, offset):
        raise NotImplementedError('Target does not define reg_load_offset')

    def jump_reg(self, reg):
        raise NotImplementedError('Target does not define a jump to register method')

    def syscall(self, op):
        raise NotImplementedError('Target does not define syscall method')

    def data_finalizer(self, code, data):
        raise NotImplementedError('Target does not define a data finalizer')

    def reg_load_array(self, reg, value):
        temp_reg = self.TEMP_REG[self.target.bits]
        code = []

        if value:
            for item in reversed(value):
                if isinstance(item, (six.text_type, six.binary_type)):
                    item = self.alloc_data(item)

                if isinstance(item, Offset) and not item:
                    item = self.OFFSET_REG

                if not isinstance(item, Register):
                    code.extend(self.reg_load(temp_reg, item))
                    item = temp_reg

                code.extend(self.reg_push(item))

        code.extend(self.reg_load(reg, self.STACK_REG))
        return code

    def reg_load(self, reg, value):
        """
        Load a value into a register. The value can be a string or binary (in
        which case the value is passed to :meth:`alloc_data`), another
        :class:`Register`, an :class:`Offset` or :class:`Buffer`, an integer
        immediate, a ``list`` or ``tuple`` or a syscall invocation.

        Arguments:
            reg(pwnypack.shellcode.types.Register): The register to load the
                value into.
            value: The value to load into the register.

        Returns:
            list: A list of mnemonics that will load value into reg.
        """

        if isinstance(value, (six.text_type, six.binary_type)):
            value = self.alloc_data(value)

        if value is None:
            return self.reg_load_imm(reg, 0)

        elif isinstance(value, Register):
            if reg is not value:
                return self.reg_load_reg(reg, value)
            else:
                return []

        elif isinstance(value, Offset):
            if value:
                return self.reg_load_offset(reg, value)
            else:
                return self.reg_load(reg, self.OFFSET_REG)

        elif isinstance(value, Buffer):
            return self.reg_load_offset(reg, sum(len(v) for v in six.iterkeys(self.data)) + value.offset)

        elif isinstance(value, six.integer_types):
            reg_width = self.REGISTER_WIDTH[reg]
            if value < -2 ** (reg_width-1):
                raise ValueError('%d does not fit %s' % (value, reg))
            elif value >= 2 ** reg_width:
                raise ValueError('%d does not fit %s' % (value, reg))
            return self.reg_load_imm(reg, value)

        elif isinstance(value, (list, tuple)):
            return self.reg_load_array(reg, value)

        elif isinstance(value, SyscallInvoke):
            return self.syscall(value) + self.reg_load(reg, self.SYSCALL_RET_REG)

        else:
            raise TypeError('Invalid argument type "%s"' % repr(value))

    def reg_add(self, reg, value):
        """
        Add a value to a register. The value can be another :class:`Register`,
        an :class:`Offset`, a :class:`Buffer`, an integer or ``None``.

        Arguments:
            reg(pwnypack.shellcode.types.Register): The register to add the
                value to.
            value: The value to add to the register.

        Returns:
            list: A list of mnemonics that will add ``value`` to ``reg``.
        """

        if value is None:
            return []

        elif isinstance(value, Register):
            return self.reg_add_reg(reg, value)

        elif isinstance(value, (Buffer, six.integer_types)):
            if isinstance(reg, Buffer):
                value = sum(len(v) for v in six.iterkeys(self.data)) + value.offset

            if not value:
                return []

            reg_width = self.REGISTER_WIDTH[reg]
            if value < -2 ** (reg_width-1):
                raise ValueError('%d does not fit %s' % (value, reg))
            elif value >= 2 ** reg_width:
                raise ValueError('%d does not fit %s' % (value, reg))

            if value > 0:
                return self.reg_add_imm(reg, value)
            else:
                return self.reg_sub_imm(reg, -value)

        else:
            raise ValueError('Invalid argument type "%s"' % repr(value))

    def reg_sub(self, reg, value):
        if value is None:
            return []
        elif isinstance(value, Register):
            return self.reg_sub_reg(reg, value)
        elif isinstance(value, Buffer):
            value = sum(len(v) for v in six.iterkeys(self.data)) + value.offset
            return self.reg_add(reg, -value)
        elif isinstance(value, six.integer_types):
            return self.reg_add(reg, -value)
        else:
            raise ValueError('Invalid argument type "%s"' % repr(value))

    def finalize(self, code):
        return self.PREAMBLE + code

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
                    code.extend(self.syscall(op))
                elif isinstance(op, LoadRegister):
                    code.extend(self.reg_load(op.register, op.value))
                elif isinstance(op, str):
                    code.extend(op.split('\n'))
                else:
                    raise ValueError('No idea how to assemble "%s"' % repr(op))
            return ['\t%s' % line for line in code]

        # We do 2 passes to make sure all data is allocated so buffers point at the right offset.
        _compile()
        return '\n'.join(self.finalize(self.data_finalizer(_compile(), self.data))) + '\n'

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
    @first_kwonly_arg('output')
    def translate(cls, f=None, output=0, **kwargs):
        """translate(f=None, *, output=TranslateOutput.code, **kwargs)
        Decorator that turns a function into a shellcode emitting function.

        Arguments:
            f(callable): The function to decorate. If ``f`` is ``None`` a
                decorator will be returned instead.
            output(~pwnypack.shellcode.base.BaseEnvironment.TranslateOutput): The output
                format the shellcode function will produce.
            **kwargs: Keyword arguments are passed to shellcode environment
                constructor.

        Returns:
            A decorator that will translate the given function into a
            shellcode generator

        Examples:
            >>> from pwny import *
            >>> @sc.LinuxX86Mutable.translate
            ... def shellcode():
            ...     sys_exit(0)

            >>> @sc.LinuxX86Mutable.translate(output=1)
            ... def shellcode():
            ...     sys_exit(0)
        """

        def decorator(f):
            @functools.wraps(f)
            def proxy(*p_args, **p_kwargs):
                env = cls(**kwargs)
                result = translate(env, f, *p_args, **p_kwargs)
                if output == cls.TranslateOutput.code:
                    return env.assemble(result)
                elif output == cls.TranslateOutput.assembly:
                    return env.target, env.compile(result)
                else:
                    return env, result
            return proxy

        if f is None:
            return decorator
        else:
            return decorator(f)
