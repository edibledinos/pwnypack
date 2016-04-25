"""
This module contains functions that allow you to manipulate, encode or decode
strings and byte sequences.
"""


import base64
import re
import string
import itertools
import six
import codecs
from kwonly_args import kwonly_defaults
import pwnypack.main
import binascii
from six.moves import range
from six.moves.urllib.parse import quote, quote_plus, unquote, unquote_plus, urlencode, parse_qs
try:
    from collections import Counter
except ImportError:
    from counter import Counter


__all__ = [
    'xor',
    'find_xor_mask',
    'rot13',
    'caesar',
    'enhex',
    'dehex',
    'enb64',
    'deb64',
    'enurlform',
    'deurlform',
    'enurlquote',
    'deurlquote',
    'frequency',
]


def xor(key, data):
    """
    Perform cyclical exclusive or operations on ``data``.

    The ``key`` can be a an integer *(0 <= key < 256)* or a byte sequence. If
    the key is smaller than the provided ``data``, the ``key`` will be
    repeated.

    Args:
        key(int or bytes): The key to xor ``data`` with.
        data(bytes): The data to perform the xor operation on.

    Returns:
        bytes: The result of the exclusive or operation.

    Examples:
        >>> from pwny import *
        >>> xor(5, b'ABCD')
        b'DGFA'
        >>> xor(5, b'DGFA')
        b'ABCD'
        >>> xor(b'pwny', b'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        b'15-=51)19=%5=9!)!%=-%!9!)-'
        >>> xor(b'pwny', b'15-=51)19=%5=9!)!%=-%!9!)-')
        b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    """

    if type(key) is int:
        key = six.int2byte(key)
    key_len = len(key)

    return b''.join(
        six.int2byte(c ^ six.indexbytes(key, i % key_len))
        for i, c in enumerate(six.iterbytes(data))
    )


@kwonly_defaults
def find_xor_mask(data, alphabet=None, max_depth=3, min_depth=0, iv=None):
    """
    Produce a series of bytestrings that when XORed together end up being
    equal to ``data`` and only contain characters from the giving
    ``alphabet``. The initial state (or previous state) can be given as
    ``iv``.

    Arguments:
        data (bytes): The data to recreate as a series of XOR operations.
        alphabet (bytes): The bytestring containing the allowed characters
            for the XOR values. If ``None``, all characters except NUL bytes,
            carriage returns and newlines will be allowed.
        max_depth (int): The maximum depth to look for a solution.
        min_depth (int): The minimum depth to look for a solution.
        iv (bytes): Initialization vector. If ``None``, it will be assumed the
            operation starts at an all zero string.

    Returns:
        A list of bytestrings that, when XOR'ed with ``iv`` (or just eachother
        if ``iv` is not providede) will be the same as ``data``.

    Examples:
        Produce a series of strings that when XORed together will result in
        the string 'pwnypack' using only ASCII characters in the range 65 to
        96:

        >>> from pwny import *
        >>> find_xor_mask('pwnypack', alphabet=''.join(chr(c) for c in range(65, 97)))
        [b'````````', b'AAAAABAA', b'QVOXQCBJ']
        >>> xor(xor(b'````````', b'AAAAABAA'), b'QVOXQCBJ')
        'pwnypack'
    """

    if alphabet is None:
        alphabet = set(i for i in range(256) if i not in (0, 10, 13))
    else:
        alphabet = set(six.iterbytes(alphabet))

    if iv is None:
        iv = b'\0' * len(data)

    if len(data) != len(iv):
        raise ValueError('length of iv differs from data')

    if not min_depth and data == iv:
        return []
    data = xor(data, iv)

    # Pre-flight check to see if we have all the bits we need.
    mask = 0
    for ch in alphabet:
        mask |= ch
    mask = ~mask

    # Map all bytes in data into a {byte: [pos...]} dictionary, check
    # if we have enough bits along the way.
    data_map_tmpl = {}
    for i, ch in enumerate(six.iterbytes(data)):
        if ch & mask:
            raise ValueError('Alphabet does not contain enough bits.')
        data_map_tmpl.setdefault(ch, []).append(i)

    # Let's try to find a solution.
    for depth in range(max(min_depth, 1), max_depth + 1):
        # Prepare for round.
        data_map = data_map_tmpl.copy()
        results = [[None] * len(data) for _ in range(depth)]

        for values in itertools.product(*([alphabet] * (depth - 1))):
            # Prepare cumulative mask for this combination of alphabet.
            mask = 0
            for value in values:
                mask ^= value

            for ch in list(data_map):
                r = ch ^ mask
                if r in alphabet:
                    # Found a solution for this character, mark the result.
                    pos = data_map.pop(ch)
                    for p in pos:
                        results[0][p] = r
                        for i, value in enumerate(values):
                            results[i + 1][p] = value

                    if not data_map:
                        # Aaaand.. We're done!
                        return [
                            b''.join(six.int2byte(b) for b in r)
                            for r in results
                        ]

        # No solution found at this depth. Increase depth, try again.

    raise ValueError('No solution found.')


def caesar(shift, data, shift_ranges=('az', 'AZ')):
    """
    Apply a caesar cipher to a string.

    The caesar cipher is a substition cipher where each letter in the given
    alphabet is replaced by a letter some fixed number down the alphabet.

    If ``shift`` is ``1``, *A* will become *B*, *B* will become *C*, etc...

    You can define the alphabets that will be shift by specifying one or more
    shift ranges. The characters will than be shifted within the given ranges.

    Args:
        shift(int): The shift to apply.
        data(str): The string to apply the cipher to.
        shift_ranges(list of str): Which alphabets to shift.

    Returns:
        str: The string with the caesar cipher applied.

    Examples:
        >>> caesar(16, 'Pwnypack')
        'Fmdofqsa'
        >>> caesar(-16, 'Fmdofqsa')
        'Pwnypack'
        >>> caesar(16, 'PWNYpack', shift_ranges=('AZ',))
        'FMDOpack'
        >>> caesar(16, 'PWNYpack', shift_ranges=('Az',))
        '`g^iFqsA'
    """
    alphabet = dict(
        (chr(c), chr((c - s + shift) % (e - s + 1) + s))
        for s, e in map(lambda r: (ord(r[0]), ord(r[-1])), shift_ranges)
        for c in range(s, e + 1)
    )
    return ''.join(alphabet.get(c, c) for c in data)


rot13_encode = codecs.getencoder('rot-13')
rot13 = lambda d: rot13_encode(d)[0]
rot13.__doc__ = """
Rotate all characters in the alphabets A-Z and a-z by 13 positions in the
alphabet. This is a :func:`caesar` shift of 13 along the fixed alphabets
``A-Z`` and ``a-z``.

Args:
    d(str): The string to the apply the cipher to.

Returns:
    str: The string with the rot13 cipher applied.

Examples:
    >>> rot13('whax')
    'junk'
    >>> rot13('junk')
    'whax'
"""


def enhex(d, separator=''):
    """
    Convert bytes to their hexadecimal representation, optionally joined by a
    given separator.

    Args:
        d(bytes): The data to convert to hexadecimal representation.
        separator(str): The separator to insert between hexadecimal tuples.

    Returns:
        str: The hexadecimal representation of ``d``.

    Examples:
        >>> from pwny import *
        >>> enhex(b'pwnypack')
        '70776e797061636b'
        >>> enhex(b'pwnypack', separator=' ')
        '70 77 6e 79 70 61 63 6b'
    """

    v = binascii.hexlify(d).decode('ascii')
    if separator:
        return separator.join(
            v[i:i+2]
            for i in range(0, len(v), 2)
        )
    else:
        return v


dehex_clean = re.compile('[^a-fA-F0-9]')
dehex = lambda d: binascii.unhexlify(dehex_clean.sub('', d).encode('ascii'))
dehex.__doc__ = """
Convert a hexadecimal representation of a byte sequence to bytes. All
non-hexadecimal characters will be removed from the input.

Args:
    d(str): The string of hexadecimal tuples.

Returns:
    bytes: The byte sequence represented by ``d``.

Examples:
    >>> from pwny import *
    >>> dehex('70776e797061636b')
    b'pwnypack'
    >>> dhex('70 77 6e 79 70 61 63 6b')
    b'pwnypack'
"""


enb64 = lambda d: base64.b64encode(d).decode('ascii')
enb64.__doc__ = """
Convert bytes to their base64 representation.

Args:
    d(bytes): The data to convert to its base64 representation.

Returns:
    str: The base64 representation of ``d``.

Example:
    >>> from pwny import *
    >>> enb64(b'pwnypack')
    'cHdueXBhY2s='
"""


deb64 = lambda d: base64.b64decode(d.encode('ascii'))
deb64.__doc__ = """
Convert a base64 representation back to its original bytes.

Args:
    d(str): The base64 representation to decode.

Returns:
    bytes: The bytes represented by ``d``.

Example:
    >>> from pwny import *
    >>> deb64('cHdueXBhY2s=')
    b'pwnypack'
"""


def enurlform(q):
    """
    Convert a dictionary to a URL encoded query string.

    Args:
        q(dict): The query to encode.

    Returns:
        str: The urlencoded representation of ``q``.

    Example:
        >>> from pwny import *
        >>> enurlform({'foo': 'bar', 'baz': ['quux', 'corge']})
        'foo=bar&baz=quux&baz=corge'
    """
    return urlencode(q, doseq=True)


def deurlform(d):
    """
    Convert a URL encoded query string to a dictionary.

    Args:
        d(str): The URL encoded query string.

    Returns:
        dict: A dictionary containing each key and all its values as a list.

    Example:
        >>> from pwny import *
        >>> deurlform('foo=bar&baz=quux&baz=corge')
        {'foo': ['bar'], 'baz': ['quux', 'corge']}
    """
    return parse_qs(d)


def enurlquote(v, plus=False):
    """
    Percent encode a string for use in an URL.

    Args:
        v(str): The value to percent encode.
        plus(bool): Use a plus symbol for spaces, otherwise use %20.

    Returns:
        str: The percent encoded string.

    Example:
        >>> from pwny import *
        >>> enurlquote('Foo Bar/Baz', True)
        'Foo+Bar/Baz
    """
    return quote_plus(v) if plus else quote(v)


def deurlquote(d, plus=False):
    """
    Decode a percent encoded string.

    Args:
        d(str): The percent encoded value to decode.
        plus(bool): Parse a plus symbol as a space.

    Returns:
        str: The decoded version of the percent encoded of ``d``.

    Example:
        >>> from pwny import *
        >>> deurlquote('Foo+Bar/Baz')
        'Foo Bar/Baz'
    """
    return unquote_plus(d) if plus else unquote(d)


frequency = lambda v: dict(Counter(v))
frequency.__doc__ = """
Perform a frequency analysis on a byte sequence or string.

Args:
    d(bytes or str): The sequence to analyse.

Returns:
    dict: A dictionary of unique elements in ``d`` and how often the occur.

Example:
    >>> frequency('pwnypack')
    {'a': 1, 'c': 1, 'k': 1, 'n': 1, 'p': 2, 'w': 1, 'y': 1}
"""


@pwnypack.main.register('xor')
def xor_app(parser, cmd, args):  # pragma: no cover
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
def caesar_app(parser, cmd, args):  # pragma: no cover
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
def rot13_app(parser, cmd, args):  # pragma: no cover
    """
    rot13 encrypt a value.
    """

    parser.add_argument('value', help='the value to rot13, read from stdin if omitted', nargs='?')
    args = parser.parse_args(args)
    return rot13(pwnypack.main.string_value_or_stdin(args.value))


@pwnypack.main.register('enb64')
def enb64_app(parser, cmd, args):  # pragma: no cover
    """
    base64 encode a value.
    """

    parser.add_argument('value', help='the value to base64 encode, read from stdin if omitted', nargs='?')
    args = parser.parse_args(args)
    return enb64(pwnypack.main.binary_value_or_stdin(args.value))


@pwnypack.main.register('deb64')
def deb64_app(parser, cmd, args):  # pragma: no cover
    """
    base64 decode a value.
    """

    parser.add_argument('value', help='the value to base64 decode, read from stdin if omitted', nargs='?')
    args = parser.parse_args(args)
    return deb64(pwnypack.main.string_value_or_stdin(args.value))


@pwnypack.main.register('enhex')
def enhex_app(parser, cmd, args):  # pragma: no cover
    """
    hex encode a value.
    """

    parser.add_argument('value', help='the value to hex encode, read from stdin if omitted', nargs='?')
    parser.add_argument(
        '--separator', '-s',
        default='',
        help='the separator to place between hex tuples'
    )
    args = parser.parse_args(args)
    return enhex(pwnypack.main.binary_value_or_stdin(args.value), args.separator)


@pwnypack.main.register('dehex')
def dehex_app(parser, cmd, args):  # pragma: no cover
    """
    hex decode a value.
    """

    parser.add_argument('value', help='the value to base64 decode, read from stdin if omitted', nargs='?')
    args = parser.parse_args(args)
    return dehex(pwnypack.main.string_value_or_stdin(args.value))


@pwnypack.main.register('enurlform')
def enurlform_app(parser, cmd, args):  # pragma: no cover
    """
    encode a series of key=value pairs into a query string.
    """

    parser.add_argument('values', help='the key=value pairs to URL encode', nargs='+')
    args = parser.parse_args(args)
    return enurlform(dict(v.split('=', 1) for v in args.values))


@pwnypack.main.register('deurlform')
def deurlform_app(parser, cmd, args):  # pragma: no cover
    """
    decode a query string into its key value pairs.
    """

    parser.add_argument('value', help='the query string to decode')
    args = parser.parse_args(args)
    return ' '.join('%s=%s' % (key, value) for key, values in deurlform(args.value).items() for value in values)


@pwnypack.main.register('frequency')
def frequency_app(parser, cmd, args):  # pragma: no cover
    """
    perform frequency analysis on a value.
    """

    parser.add_argument('value', help='the value to analyse, read from stdin if omitted', nargs='?')
    args = parser.parse_args(args)
    data = frequency(six.iterbytes(pwnypack.main.binary_value_or_stdin(args.value)))
    return '\n'.join(
        '0x%02x (%c): %d' % (key, chr(key), value)
        if key >= 32 and chr(key) in string.printable else
        '0x%02x ---: %d' % (key, value)
        for key, value in data.items()
    )
