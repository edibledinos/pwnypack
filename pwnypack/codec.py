import base64
import collections
import string


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
        key = chr(key)
    key_len = len(key)

    return ''.join(
        chr(ord(c) ^ ord(key[i % key_len]))
        for i, c in enumerate(data)
    )


rot13 = lambda d: d.encode('rot13')


def caesar(shift, data, shift_ranges=('az', 'AZ')):
    alphabet = {
        chr(c): chr((c - s + shift) % (e - s + 1) + s)
        for s, e in map(lambda r: (ord(r[0]), ord(r[-1])), shift_ranges)
        for c in range(s, e + 1)
    }
    return ''.join(alphabet.get(c, c) for c in data)


enhex = lambda d: d.encode('hex')
dehex = lambda d: ''.join(d.split()).decode('hex')

enb64 = base64.b64encode
deb64 = base64.b64decode


frequency = collections.Counter
