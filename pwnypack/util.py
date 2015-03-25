from six.moves import range
import re
import binascii
import pwnypack.main
import pwnypack.codec


__all__ = [
    'cycle',
    'reghex',
]


def deBruijn(n, k):
    '''
    An implementation of the FKM algorithm for generating the de Bruijn
    sequence containing all k-ary strings of length n, as described in
    "Combinatorial Generation" by Frank Ruskey.
    '''

    a = [ 0 ] * (n + 1)

    def gen(t, p):
        if t > n:
            for v in a[1:p + 1]:
                yield v
        else:
            a[t] = a[t - p]
         
            for v in gen(t + 1, p):
                yield v
         
            for j in range(a[t - p] + 1, k):
                a[t] = j
                for v in gen(t + 1, t):
                    yield v

    return gen(1, 1)


def cycle(length, width=4, **kwargs):
    iter = deBruijn(width, 26)
    return ''.join([chr(ord('A') + next(iter)) for i in range(length)])


def find(key, width=4):
    key_len = len(key)
    buf = ''

    iter = deBruijn(width, 26)

    for i in range(key_len):
        buf += chr(ord('A') + next(iter))

    if buf == key:
        return 0

    for i, c in enumerate(iter):
        buf = buf[1:] + chr(ord('A') + c)
        if buf == key:
            return i + 1

    return -1


cycle.find = find
del find


reghex_regex = re.compile(r'([?.])(\{(\d+)\})?|(\*|\+)')


def reghex(pattern):
    try:
        b_pattern = b''

        last_index = 0
        for match in reghex_regex.finditer(pattern):
            index = match.start()
            b_pattern += pwnypack.codec.dehex(pattern[last_index:index])

            if match.group(1) == '?':
                length = match.group(3)
                if length is None:
                    b_pattern += b'.?'
                else:
                    b_pattern += ('.{0,%d}?' % int(length)).encode('ascii')
            elif match.group(1) == '.':
                length = match.group(3)
                if length is None:
                    b_pattern += b'.'
                else:
                    b_pattern += b'.' * int(length)
            else:
                b_pattern += b'.' + match.group(4).encode('ascii') + b'?'
            last_index = match.end()

        b_pattern += pwnypack.codec.dehex(pattern[last_index:])

        return re.compile(b_pattern)
    except (TypeError, binascii.Error, re.error):
        raise SyntaxError('Invalid rehex pattern.')


@pwnypack.main.register('cycle')
def cycle_app(parser, cmd, args):  # pragma: no cover
    """
    Generate a de Bruijn sequence of a given length.
    """

    parser.add_argument('-w', '--width', type=int, default=4, help='the length of the cycled value')
    parser.add_argument('length', type=int, help='the cycle length to generate')
    args = parser.parse_args(args)
    return cycle(args.length, args.width)


@pwnypack.main.register('cycle-find')
def cycle_find_app(parser, cmd, args):  # pragma: no cover
    """
    Find the first position of a value in a de Bruijn sequence.
    """

    parser.add_argument('-w', '--width', type=int, default=4, help='the length of the cycled value')
    parser.add_argument('value', help='the value to determine the position of, read from stdin if missing', nargs='?')
    args = parser.parse_args(args)
    return 'Found at position: %d' % cycle.find(pwnypack.main.string_value_or_stdin(args.value), args.width)
