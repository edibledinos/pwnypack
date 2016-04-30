import pwny


def test_cycle():
    assert pwny.cycle(64) == 'AAAABAAACAAADAAAEAAAFAAAGAAAHAAAIAAAJAAAKAAALAAAMAAANAAAOAAAPAAA'


def test_cycle_width():
    assert pwny.cycle(64, width=2) == 'AABACADAEAFAGAHAIAJAKALAMANAOAPAQARASATAUAVAWAXAYAZBBCBDBEBFBGBH'


def test_cycle_find():
    assert pwny.cycle_find('PAAA') == 60


def test_cycle_find_start():
    assert pwny.cycle_find('AAAA') == 0


def test_cycle_find_not_found():
    assert pwny.cycle_find('\x00', width=1) == -1


def test_reghex_pattern_char():
    assert pwny.reghex('28').match(b'(') is not None
