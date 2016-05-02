import six

from pwnypack.packing import U


def _load_push(env, value):
    temp_reg = env.TEMP_REG[env.target.bits]
    return env.reg_load(temp_reg, value) + \
           env.reg_push(temp_reg)


def stack_data_finalizer(stack_align, push_strategy=_load_push):
    def proxy(env, code, data):
        reg_width = env.target.bits // 8

        data = (b''.join(six.iterkeys(data)))[::-1]
        data_size = len(data)

        data_adjust = reg_width - (data_size % reg_width)
        if data_adjust != reg_width:
            data += b'\xff' * data_adjust
            data_size += data_adjust

        buffer_size = sum(buffer.length for buffer in env.buffers)
        stack_size = buffer_size + data_size
        stack_adjust = stack_align - (stack_size % stack_align)
        if stack_adjust != stack_align:
            stack_size += stack_adjust

        push_code = env.reg_sub(env.STACK_REG, stack_size - data_size)

        while data:
            chunk, data = data[:reg_width], data[reg_width:]
            push_code.extend(push_strategy(env, U(chunk[::-1], target=env.target)))

        push_code.extend(env.reg_load(env.OFFSET_REG, env.STACK_REG))
        if data_adjust != reg_width:
            push_code.extend(env.reg_add(env.OFFSET_REG, data_adjust))

        return ['\t%s' % line for line in push_code] + code
    return proxy
