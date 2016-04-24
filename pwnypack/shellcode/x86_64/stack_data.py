from pwnypack.shellcode.stack_data import stack_data_finalizer


def _load_push(env, value):
    return env.reg_load(env.RBX, value) + \
           env.reg_push(env.RBX)


def x86_64_null_safe_stack_data_finalizer(stack_align):
    return stack_data_finalizer(stack_align, _load_push)
