import six


__all__ = [
    'php_serialize',
    'PhpObject',
]


def php_serialize(value):
    """
    Serialize a value for use with PHP's deserialize() function. This function
    can serialize bytes, strings, integers, floats, booleans, None, lists,
    dicts and custom objects implementing __php__().

    Args:
        value: The value to serialize.

    Returns:
        bytes: The serialized form of `value` ready to be unserialized by PHP.

    Example:
        >>> from pwny import *
        >>> php_serialize([b'foo', u'bar', 42, 2.5, True, None, {'a': 'b'}])
        b'a:7:{i:0;s:3:"foo";i:1;s:3:"bar";i:2;i:42;i:3;d:2.5;i:4;b:1;i:5;N;i:6;a:1:{s:1:"a";s:1:"b";}}'
    """

    def serialize_array(items):
        content = b''.join(
            php_serialize(i) + php_serialize(v)
            for i, v in items
        )
        return 'a:{0}:'.format(len(value)).encode('utf8') + b'{' + content + b'}'

    def serialize_str(prefix, item):
        return prefix + b':' + str(item).encode('utf8') + b';'

    if isinstance(value, six.binary_type):
        return b's:' + str(len(value)).encode('utf8') + b':"' + value + b'";'
    elif isinstance(value, six.text_type):
        return php_serialize(value.encode('utf8'))
    elif isinstance(value, bool):
        return serialize_str(b'b', 1 if value else 0)
    elif isinstance(value, int):
        return serialize_str(b'i', value)
    elif isinstance(value, float):
        return serialize_str(b'd', value)
    elif value is None:
        return b'N;'
    elif isinstance(value, (list, tuple)):
        return serialize_array(enumerate(value))
    elif isinstance(value, dict):
        return serialize_array(six.iteritems(value))
    else:
        return value.__php__()


class PhpObject(object):
    """
    Helper class to represent PHP objects for serialization using
    :func:`php_serialize`.

    Instances of this class act like a dictionary of properties that should
    be set on the deserialized PHP instance. You can prefix the property
    names with ``'public '``,  ``'protected '`` or ``'private '`` to ensure
    the correct instance variables are set.

    Arguments:
        class_name(str): The name of the PHP class to use when
            deserializing.
        properties(dict): The properties to deserialize in this instance.

    Example:
        >>> from pwny import *
        >>> o = PhpObject('Foo\\Bar', {'protected fg': '#000000'})
        >>> php_serialize(o)
        b'O:7:"Foo\\Bar":1:{s:5:"\\x00*\\x00fg";s:7:"#000000";}'
    """

    def __init__(self, class_name, properties=None):
        self.class_name = class_name
        self.items = {}
        for k, v in six.iteritems(properties or {}):
            self[k] = v

    def _mogrify_key(self, key):
        if key.startswith('protected '):
            return '\0*\0' + key.split(' ', 1)[1]
        elif key.startswith('private '):
            return self.class_name + key.split(' ', 1)[1]
        elif key.startswith('public '):
            return key.split(' ', 1)[1]
        else:
            return key

    def __setitem__(self, key, value):
        self.items[self._mogrify_key(key)] = value

    def __getitem__(self, key):
        return self.items[self._mogrify_key(key)]

    def __php__(self):
        properties = b''.join(
            php_serialize(k) + php_serialize(v)
            for k, v in six.iteritems(self.items)
        )
        return 'O:{0}:"{1}":{2}:'.format(len(self.class_name), self.class_name, len(self.items)).encode('utf8') + \
            b'{' + properties + b'}'
