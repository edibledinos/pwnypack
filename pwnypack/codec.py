import base64
import collections
import string
import six
import codecs
import pwnypack.main


__all__ = [
    'xor',
    'rot13',
    'caesar',
    'enhex',
    'dehex',
    'enb64',
    'deb64',
    'frequency',
]


def xor(key, data):
    if type(key) is int:
        key = six.int2byte(key)
    key_len = len(key)

    return b''.join(
        six.int2byte(c ^ six.indexbytes(key, i % key_len))
        for i, c in enumerate(six.iterbytes(data))
    )


def caesar(shift, data, shift_ranges=('az', 'AZ')):
    alphabet = {
        chr(c): chr((c - s + shift) % (e - s + 1) + s)
        for s, e in map(lambda r: (ord(r[0]), ord(r[-1])), shift_ranges)
        for c in range(s, e + 1)
    }
    return ''.join(alphabet.get(c, c) for c in data)


rot13_encode = codecs.getencoder('rot-13')
rot13 = lambda d: rot13_encode(d)[0]

hex_encode = codecs.getencoder('hex')
hex_decode = codecs.getdecoder('hex')
enhex = lambda d: hex_encode(d)[0].decode('ascii')
dehex = lambda d: hex_decode(''.join(d.replace(':', '').split()))[0]


enb64 = lambda d: base64.b64encode(d).decode('ascii')
deb64 = lambda d: base64.b64decode(d.encode('ascii'))


frequency = collections.Counter


@pwnypack.main.register('xor')
def xor_app(parser, cmd, args):
    """
    Xor a value with a key.
    """

    parser.add_argument(
        '-d', '--dec',
        help='interpret the key as a decimal integer',
        dest='type',
        action='store_const',
        const=int
    )
    parser.add_argument(
        '-x', '--hex',
        help='interpret the key as an hexadecimal integer',
        dest='type',
        action='store_const',
        const=lambda v: int(v, 16)
    )
    parser.add_argument('key', help='the key to xor the value with')
    parser.add_argument('value', help='the value to xor, read from stdin if omitted', nargs='?')

    args = parser.parse_args(args)
    if args.type is not None:
        args.key = args.type(args.key)

    return xor(args.key, pwnypack.main.binary_value_or_stdin(args.value))


@pwnypack.main.register('caesar')
def caesar_app(parser, cmd, args):
    """
    Caesar crypt a value with a key.
    """

    parser.add_argument('shift', type=int, help='the shift to apply')
    parser.add_argument('value', help='the value to caesar crypt, read from stdin if omitted', nargs='?')
    parser.add_argument(
        '-s', '--shift-range',
        dest='shift_ranges',
        action='append',
        help='specify a character range to shift (defaults to a-z, A-Z)'
    )

    args = parser.parse_args(args)
    if not args.shift_ranges:
        args.shift_ranges = ['az', 'AZ']

    return caesar(args.shift, pwnypack.main.string_value_or_stdin(args.value), args.shift_ranges)


@pwnypack.main.register('rot13')
def rot13_app(parser, cmd, args):
    """
    rot13 encrypt a value.
    """

    parser.add_argument('value', help='the value to rot13, read from stdin if omitted', nargs='?')
    args = parser.parse_args(args)
    return rot13(pwnypack.main.string_value_or_stdin(args.value))


@pwnypack.main.register('enb64')
def enb64_app(parser, cmd, args):
    """
    base64 encode a value.
    """

    parser.add_argument('value', help='the value to base64 encode, read from stdin if omitted', nargs='?')
    args = parser.parse_args(args)
    return enb64(pwnypack.main.binary_value_or_stdin(args.value))


@pwnypack.main.register('deb64')
def deb64_app(parser, cmd, args):
    """
    base64 decode a value.
    """

    parser.add_argument('value', help='the value to base64 decode, read from stdin if omitted', nargs='?')
    args = parser.parse_args(args)
    return deb64(pwnypack.main.string_value_or_stdin(args.value))


@pwnypack.main.register('enhex')
def enhex_app(parser, cmd, args):
    """
    hex encode a value.
    """

    parser.add_argument('value', help='the value to hex encode, read from stdin if omitted', nargs='?')
    args = parser.parse_args(args)
    return enhex(pwnypack.main.binary_value_or_stdin(args.value))


@pwnypack.main.register('dehex')
def dehex_app(parser, cmd, args):
    """
    hex decode a value.
    """

    parser.add_argument('value', help='the value to base64 decode, read from stdin if omitted', nargs='?')
    args = parser.parse_args(args)
    return dehex(pwnypack.main.string_value_or_stdin(args.value))


@pwnypack.main.register('frequency')
def frequency_app(parser, cmd, args):
    """
    perform frequency analysis on a value.
    """

    parser.add_argument('value', help='the value to analyse, read from stdin if omitted', nargs='?')
    args = parser.parse_args(args)
    data = frequency(pwnypack.main.binary_value_or_stdin(args.value))
    return '\n'.join(
        '0x%02x (%c): %d' % (key, chr(key), value)
        if chr(key) in string.printable else
        '0x%02x ---: %d' % (key, value)
        for key, value in data.items()
    )
