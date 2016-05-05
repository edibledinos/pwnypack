from pwnypack.shellcode.stack_data import stack_data_finalizer


__all__ = ['x86_stack_data_finalizer']


def _push_imm32(_, chunk):
    return ['push dword %d' % chunk]


def x86_stack_data_finalizer(stack_align):
    return stack_data_finalizer(stack_align, _push_imm32)
