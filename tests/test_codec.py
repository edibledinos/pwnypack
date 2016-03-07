import pwny


def test_xor_int():
    assert pwny.xor(61, b'fooo') == b'[RRR'


def test_xor_str():
    assert pwny.xor(b'abcd', b'fooo') == b'\x07\r\x0c\x0b'
    assert pwny.xor(b'abcd', b'fooofooo') == b'\x07\r\x0c\x0b\x07\r\x0c\x0b'


def test_rot13():
    assert pwny.rot13('whax') == 'junk'


def test_caesar():
    assert pwny.caesar(1, 'abcXYZ') == 'bcdYZA'


def test_enhex():
    assert pwny.enhex(b'ABCD') == '41424344'


def test_dehex():
    assert pwny.dehex('41424344') == b'ABCD'


def test_enb64():
    assert pwny.enb64(b'ABCD') == 'QUJDRA=='


def test_deb64():
    assert pwny.deb64('QUJDRA==') == b'ABCD'


def test_deurlform():
    assert pwny.deurlform('foo=bar&baz=quux&baz=corge') == {'foo': ['bar'], 'baz': ['quux', 'corge']}


def test_enurlform():
    assert pwny.enurlform((('foo', 'bar'), ('baz', ['quux', 'corge']))) == 'foo=bar&baz=quux&baz=corge'


def test_enurlquote():
    assert pwny.enurlquote('Foo Bar/Baz') == 'Foo%20Bar/Baz'


def test_enurlquote_plus():
    assert pwny.enurlquote('Foo Bar/Baz', plus=True) == 'Foo+Bar%2FBaz'


def test_deurlquote():
    assert pwny.deurlquote('Foo%20Bar%2FBaz') == 'Foo Bar/Baz'


def test_deurlquote_no_plus():
    assert pwny.deurlquote('Foo+Bar%2FBaz') == 'Foo+Bar/Baz'


def test_deurlquote_plus():
    assert pwny.deurlquote('Foo+Bar%2FBaz', True) == 'Foo Bar/Baz'


def test_frequency():
    assert pwny.frequency('ABCD') == {'A': 1, 'B': 1, 'C': 1, 'D': 1}
