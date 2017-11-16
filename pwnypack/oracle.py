"""
This module provides a functions that, given an oracle function that returns
``True`` when a message is properly padded and ``False`` otherwise, will
decrypt or encrypt a given message assuming that the underlying cipher
operates in CBC mode.
"""

from __future__ import print_function, division

import functools
import multiprocessing
import threading

import os
from six.moves import map, range

__all__ = ['padding_oracle_decrypt', 'padding_oracle_encrypt']


def interruptable_iter(event, iterable):
    for value in iterable:
        yield value
        if event.is_set():
            break


def consult_oracle(oracle, chunk, block, is_last_byte):
    if not oracle(bytes(chunk + block)):
        return False

    if is_last_byte:
        chunk[-2] ^= 0x01
        if not oracle(bytes(chunk + block)):
            return False

    return True


def check_padding_decrypt(event, oracle, block_len, chunk, block, plain, i, j):
    if event.is_set():
        return None

    chunk, plain = chunk[:], plain[:]

    plain[i] = j
    chunk[i] ^= j

    if consult_oracle(oracle, chunk, block, i == block_len - 1):
        event.set()
        return plain


def decrypt_block(oracle, block_len, alphabet, pool, progress, params):
    start, prev, block, prefix, suffix, is_last_block = params

    if pool is not None:
        event_factory = multiprocessing.Manager().Event
        map_func = pool.imap_unordered
    else:
        event_factory = threading.Event
        map_func = map

    plain = bytearray([0] * block_len)

    for i, j in enumerate(prefix):
        plain[i] = j
        if progress is not None:
            progress(start + i, j)

    for i, j in enumerate(reversed(suffix)):
        plain[block_len - i - 1] = j
        if progress is not None:
            progress(start + block_len - i - 1, j)

    in_padding = is_last_block and not suffix

    i = block_len - 1 - len(suffix)
    while i >= len(prefix):
        chunk = prev[:]

        for k in range(i, block_len):
            chunk[k] ^= plain[k] ^ (block_len - i)

        event = event_factory()
        f = functools.partial(check_padding_decrypt, event, oracle, block_len, chunk, block, plain, i)

        if in_padding:
            _alphabet = range(1, 17)
        else:
            _alphabet = alphabet

        for result in map_func(f, interruptable_iter(event, _alphabet)):
            if result is not None:
                plain = result

        if not event.is_set():
            raise RuntimeError('Oracle is unstable')

        if in_padding:
            in_padding = False
            pad_value = plain[-1]
            for j in range(block_len - pad_value, i):
                plain[j] = pad_value
                if progress is not None:
                    progress(start + j, pad_value)
            i -= pad_value
        else:
            if progress is not None:
                progress(start + i, plain[i])
            i -= 1

    return plain


def block_pairs(block_len, data, known_prefix, known_suffix):
    data_len = len(data)
    suffix_len = len(known_suffix)
    for prev, start, suffix_start in zip(range(data_len - block_len * 2, -1, -block_len),
                                         range(data_len - block_len, -1, -block_len),
                                         range(suffix_len - block_len, -data_len - 1, -block_len)):
        yield (
            prev,
            data[prev:start],
            data[start:start + block_len],
            known_prefix[prev:start],
            known_suffix[max(suffix_start, 0):max(suffix_start + block_len, 0)],
            start + block_len == data_len
        )


def padding_oracle_decrypt(oracle, ciphertext, known_prefix=b'', known_suffix=b'', block_size=128,
                           alphabet=None, pool=None, block_pool=None, progress=None):
    """
    Decrypt ciphertext using an oracle function that returns ``True`` if the
    provided ciphertext is correctly PKCS#7 padded after decryption. The
    cipher needs to operate in CBC mode.

    Args:
        oracle(callable): The oracle function. Will be called repeatedly with
            a chunk of ciphertext.
        ciphertext(bytes): The data to decrypt. Should include the IV at the
            start.
        known_prefix(bytes): If the start of the plaintext is known, it can be
            provided to skip decrypting the known prefix.
        known_suffix(bytes): If the end of the plaintext is known, it can be
            provided to skip decrypting the known suffix. Should include
            padding.
        block_size(int): The cipher's block size in bits.
        alphabet(bytes): Optimize decryption if you know which characters the
            plaintext will consist of.
        pool(multiprocessing.Pool): A multiprocessing pool to use to
            parallelize the decryption. This pool is used to call the oracle
            function. Fairly heavy due to the required inter-process state
            synchronization. If ``None`` (the default), no multiprocessing
            will be used.
        block_pool(multiprocessing.Pool): A multiprocessing pool to use to
            parallelize the decryption. This pool is used to decrypt entire
            blocks in parallel. When decrypting ciphertext consisting of
            multiple blocks, it is usually more efficient than using the
            ``pool`` argument. If ``None`` (the default), no multiprocessing
            will be used.
        progress(callable): A callable that will be called each time a new
            byte is decrypted. Is called with the positition of the character
            in the plaintext result and the character itself.

    Returns:
        bytes: The decrypted data with its PKCS#7 padding stripped.

    Raises:
        RuntimeError: Raised if the oracle behaves unpredictable.

    Example:
        >>> from pwny import *
        >>> with multiprocessing.Pool(5) as pool:
        >>>     print(padding_oracle_decrypt(oracle_function, encrypted_data, pool=pool))
        b'decrypted data'
    """

    block_len = block_size // 8
    assert len(ciphertext) % block_len == 0 and len(ciphertext) >= 2 * block_len

    known_prefix = bytearray(known_prefix)
    known_suffix = bytearray(known_suffix)

    if alphabet is None:
        alphabet = bytearray(range(256))

    if block_pool is not None:
        map_func = block_pool.imap
    else:
        map_func = map

    plaintext = bytearray()

    decrypt_func = functools.partial(decrypt_block, oracle, block_len, alphabet, pool, progress)
    for plain in map_func(decrypt_func, block_pairs(block_len, bytearray(ciphertext), known_prefix, known_suffix)):
        plaintext[0:0] = plain

    return bytes(plaintext[:-plaintext[-1]])


def check_padding_encrypt(event, oracle, block_len, chunk, block, i, j):
    chunk = chunk[:]

    chunk[i] = j

    if consult_oracle(oracle, chunk, block, i == block_len - 1):
        event.set()
        return chunk


def encrypt_block(oracle, block_len, block, plain, pool):
    if pool is not None:
        event_factory = multiprocessing.Manager().Event
        map_func = pool.imap_unordered
    else:
        event_factory = threading.Event
        map_func = map

    cipher = bytearray([0] * block_len)

    for i in range(block_len - 1, -1, -1):
        chunk = cipher[:]

        for k in range(i + 1, block_len):
            chunk[k] ^= block_len - i

        event = event_factory()
        f = functools.partial(check_padding_encrypt, event, oracle, block_len, chunk, block, i)

        for result in map_func(f, interruptable_iter(event, range(256))):
            if result is not None:
                cipher[i] = result[i] ^ (block_len - i)

        if not event.is_set():
            raise RuntimeError('Oracle is unstable')

    for k, p in enumerate(plain):
        cipher[k] ^= p

    return cipher


def padding_oracle_encrypt(oracle, plaintext, block_size=128, pool=None):
    """
    Encrypt plaintext using an oracle function that returns ``True`` if the
    provided ciphertext is correctly PKCS#7 padded after decryption. The
    cipher needs to operate in CBC mode.

    Args:
        oracle(callable): The oracle function. Will be called repeatedly with
            a chunk of ciphertext.
        plaintext(bytes): The plaintext data to encrypt.
        block_size(int): The cipher's block size in bits.
        pool(multiprocessing.Pool): A multiprocessing pool to use to
            parallelize the encryption. This pool is used to call the oracle
            function. Fairly heavy due to the required inter-process state
            synchronization. If ``None`` (the default), no multiprocessing
            will be used.

    Returns:
        bytes: The encrypted data.

    Raises:
        RuntimeError: Raised if the oracle behaves unpredictable.
    """

    plaintext = bytearray(plaintext)
    block_len = block_size // 8

    padding_len = block_len - (len(plaintext) % block_len)
    plaintext.extend([padding_len] * padding_len)

    ciphertext = bytearray()

    chunk = bytearray(os.urandom(block_len))
    ciphertext[0:0] = chunk

    for plain_start in range(len(plaintext) - block_len, -1, -block_len):
        plain = plaintext[plain_start:plain_start + block_len]
        chunk = ciphertext[0:0] = encrypt_block(oracle, block_len, chunk, plain, pool)

    return bytes(ciphertext)
