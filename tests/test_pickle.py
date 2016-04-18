import pwny
from six.moves import cPickle


def func_to_invoke(a):
    return a


def test_pickle_invoke():
    data = pwny.pickle_invoke(func_to_invoke, 8)
    assert cPickle.loads(data) == 8


def test_pickle_func():
    def func_to_invoke_2(a):
        return a

    data = pwny.pickle_func(func_to_invoke_2, (8,))

    del func_to_invoke_2

    assert cPickle.loads(data) == 8
