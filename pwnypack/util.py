from six.moves import range
import pwnypack.main


__all__ = [
    'cycle',
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


@pwnypack.main.register('cycle')
def cycle_app(parser, cmd, args):
    """
    Generate a de Bruijn sequence of a given length.
    """

    parser.add_argument('-w', '--width', type=int, default=4, help='the length of the cycled value')
    parser.add_argument('length', type=int, help='the cycle length to generate')
    args = parser.parse_args(args)
    return cycle(args.length, args.width)


@pwnypack.main.register('cycle-find')
def cycle_find_app(parser, cmd, args):
    """
    Find the first position of a value in a de Bruijn sequence.
    """

    parser.add_argument('-w', '--width', type=int, default=4, help='the length of the cycled value')
    parser.add_argument('value', help='the value to determine the position of')
    args = parser.parse_args(args)
    return 'Found at position: %d' % cycle.find(args.value, args.width)
