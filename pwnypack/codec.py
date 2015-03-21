import base64
import collections
import six
import codecs


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
