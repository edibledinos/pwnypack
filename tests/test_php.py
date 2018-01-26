from pwnypack.php import php_serialize, PhpObject


def test_php_serialize():
    assert php_serialize([b'foo', u'bar', 42, 2.5, True, None, {'a': 'b'}]) == \
        b'a:7:{i:0;s:3:"foo";i:1;s:3:"bar";i:2;i:42;i:3;d:2.5;i:4;b:1;i:5;N;i:6;a:1:{s:1:"a";s:1:"b";}}'


def test_php_object_name():
    o = PhpObject('Zend\\Object')
    assert php_serialize(o) == b'O:11:"Zend\\Object":0:{}'


def test_php_object_property():
    o = PhpObject('Test', {'a': 42})
    assert php_serialize(o) == b'O:4:"Test":1:{s:1:"a";i:42;}'


def test_php_object_public_property():
    o = PhpObject('Test', {'public a': 42})
    assert php_serialize(o) == b'O:4:"Test":1:{s:1:"a";i:42;}'


def test_php_object_protected_property():
    o = PhpObject('Test', {'protected a': 42})
    assert php_serialize(o) == b'O:4:"Test":1:{s:4:"\0*\0a";i:42;}'


def test_php_object_private_property():
    o = PhpObject('Test', {'private a': 42})
    assert php_serialize(o) == b'O:4:"Test":1:{s:7:"\0Test\0a";i:42;}'


def test_php_object_get_item():
    o = PhpObject('', {'a': 42})
    assert o['a'] == 42


def test_php_object_get_item_public():
    o = PhpObject('Test', {'public a': 42})
    assert o['a'] == 42
    assert o['public a'] == 42


def test_php_object_get_item_protected():
    o = PhpObject('Test', {'protected a': 42})
    assert o['protected a'] == 42
    assert o['\0*\0a'] == 42


def test_php_object_get_item_private():
    o = PhpObject('Test', {'private a': 42})
    assert o['private a'] == 42
    assert o['\0Test\0a'] == 42
