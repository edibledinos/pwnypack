import inspect

import six

from pwnypack.shellcode.ops import SyscallInvoke, LoadRegister
from pwnypack.shellcode.types import Register, Offset, Buffer
from pwnypack import bytecode as bc


__all__ = ['translate', 'fragment']


class Fragment(object):
    def __init__(self, f):
        self.f = f

    def __call__(self, env, *args, **kwargs):
        return translate(env, self.f, *args, **kwargs)


def fragment(f):
    """
    Decorator to turn a function into a shellcode fragment that can be called
    as a function from within a translated function.

    Arguments:
        f(callable): The function to mark as a shellcode fragment.

    Returns:
        callable: The decorated shellcode fragment.
    """

    return Fragment(f)


def translate(env, func, *args, **kwargs):
    """
    Given a shellcode environment, a function and its parameters, translate
    the function to a list of shellcode operations ready to be compiled or
    assembled using :meth:`~pwnypack.shellcode.base.BaseEnvironment.compile`
    or :meth:`~pwnypack.shellcode.base.BaseEnvironment.assemble`.

    Arguments:
        env(~pwnypack.shellcode.base.Base): An instance of a shellcode
            environment.
        func(callable): The function to translate to shellcode.
        args(...): The positional arguments for the function.
        kwargs(...): The keyword arguments for the function.

    Returns:
        list: The high-level shellcode operations.
    """

    func_code = six.get_function_code(func)
    func_globals = dict(__builtins__)
    func_globals.update(six.get_function_globals(func))

    ops = bc.disassemble(func_code.co_code)

    program = []

    f_args = inspect.getcallargs(func, *args, **kwargs)
    variables = dict(
        (func_code.co_varnames.index(arg_name), arg_value)
        for arg_name, arg_value in six.iteritems(f_args)
    )

    stack = []
    for op in ops:
        if op.name == 'LOAD_CONST':
            stack.append(func_code.co_consts[op.arg])

        elif op.name == 'LOAD_GLOBAL':
            global_name = func_code.co_names[op.arg]
            stack.append(getattr(env, global_name, func_globals.get(global_name)))

        elif op.name == 'LOAD_FAST':
            var_name = func_code.co_varnames[op.arg]
            stack.append(getattr(env, var_name, variables.get(op.arg)))

        elif op.name == 'BUILD_LIST':
            items = stack[-op.arg:]
            del stack[-op.arg:]
            stack.append(items)

        elif op.name == 'LOAD_ATTR':
            obj = stack.pop()
            stack.append(getattr(obj, func_code.co_names[op.arg]))

        elif op.name == 'CALL_FUNCTION':
            nargs = op.arg & 0xff
            nkwargs = op.arg >> 8

            if nkwargs:
                f_kwargs = dict(zip(stack[-nkwargs * 2::2], stack[-nkwargs * 2 + 1::2]))
                del stack[-nkwargs * 2:]
            else:
                f_kwargs = {}

            if nargs:
                f_args = stack[-nargs:]
                del stack[-nargs:]
            else:
                f_args = []

            f = stack.pop()
            if isinstance(f, Fragment):
                stack.append(f(env, *f_args, **f_kwargs))
            else:
                stack.append(f(*f_args, **f_kwargs))

        elif op.name == 'STORE_FAST':
            value = stack.pop()
            var_name = func_code.co_varnames[op.arg]
            var = getattr(env, var_name, variables.get(op.arg, None))
            if isinstance(var, Register):
                program.append(LoadRegister(var, value))
            else:
                variables[op.arg] = value

        elif op.name == 'POP_TOP':
            value = stack.pop()
            if isinstance(value, SyscallInvoke):
                program.append(value)
            elif isinstance(value, list):
                program.extend(value)
            else:
                raise ValueError('No idea how to compile %s' % (value,))

        elif op.name == 'RETURN_VALUE':
            stack.pop()

        elif op.name == 'DUP_TOP':
            value = stack[-1]
            if isinstance(value, SyscallInvoke):
                stack.insert(-1, env.SYSCALL_RET_REG)
            else:
                stack.append(value)

        elif op.name == 'BINARY_SUBSCR':
            index = stack.pop()
            value = stack.pop()
            stack.append(value[index])

        elif op.name == 'STORE_SUBSCR':
            index = stack.pop()
            value = stack.pop()
            new_value = stack.pop()
            var = value[index]
            if isinstance(var, Register):
                program.append(LoadRegister(var, new_value))
            else:
                value[index] = new_value

        elif op.name == 'INPLACE_ADD':
            value = stack.pop()
            reg = stack.pop()
            if not isinstance(reg, Register):
                raise TypeError('In-place addition is only supported on registers')
            program.extend(env.reg_add(reg, value))
            stack.append(reg)

        elif op.name == 'INPLACE_SUBTRACT':
            value = stack.pop()
            reg = stack.pop()
            if not isinstance(reg, Register):
                raise TypeError('In-place subtraction is only supported on registers')
            program.extend(env.reg_sub(reg, value))
            stack.append(reg)

        else:
            raise RuntimeError('Unsupported opcode: %s' % op.name)

    return program
