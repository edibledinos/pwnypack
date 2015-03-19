# pwnypack

The official _Certified Edible Dinosaurs_ CTF toolkit. *pwnypack* attempts to provide a toolset which can be used to more easily develop CTF solutions.

To import all of *pwnypack* into your global namespace, use:

```python
>>> from pwny import *
```

I promise that effort will be put into not exposing unnecessary stuff and thus overly polluting your global namespace.

For an example, check out the [Big Prison Fence](https://github.com/iksteen/pwnypack/wiki/Big-Prison-Fence) example in the wiki.

## Motivation

After seeing the excellent [pwntools](https://github.com/Gallopsled/pwntools) by Gallopsled, I got interested in building my own CTF toolkit. _pwntools_ is much more complete so you should probably use that. *pwnypack* was created mostly out of curiosity.

## Modules

*pwnypack* contains a variety of modules which can be imported individually if you do not want to import everything:

```python
>>> import pwnypack.packing
```

The available modules are listed below.

### pwnypack.target

This module defines a `Target` class that exposes information about a target platform. The `Target` exposes the machine architecture (x86/x86_64/arm/etc), the endianness of the platform (little/big) and the word size (32/64 bit). It is used throughout *pwnypack* to determine how to parse or generate machine specific structures.

If you do not specify the endianness or word size explicitly, they will assume the default for the configured architecture.

A global default target is created as `target` which defaults to an x86 or x86-64 platform depending on the host machine's word size.

You can change the properties of a target (and the default target) to match the properties of the machine you're working with. If you're working with multiple platform at the same time you can create multiple instances of `Target` which you pass to the various targetable functions.

A `Target` can also assume properties of a different instance of `Target`. This can be useful because the `ELF` parser generates subclasses of `Target`.

Examples:

```python
>>> from pwny import *
>>> target.arch
<Architecture.x86_64: 62>
>>> target.endian
<Endianness.little: 1>
>>> target.bits
64
>>> target.arch = Architecture.x86
>>> target.arch
<Architecture.x86: 3>
>>> target.endian
<Endianness.little: 1>
>>> target.bits
32
>>> target.assume(ELF.parse('exploit-me'))
```

### pwnypack.packing

Contains functions to pack and unpack structures for the default or a given target platform.

### pwnypack.util

Contains various utility methods. Currently a de Bruijn sequence generator and a function to find the first occurence of a string in a de Bruijn sequence.

### pwnypack.flow

Contains a set of classes that provide a consistent and easy to learn and use interface to a subprocess or a socket. Fairly trivial to extend to other channel types.

### pwnypack.asm

Contains a function that invokes `nasm` for you for a given target platform.

### pwnypack.elf

Contains a parser for ELF header structures.

### pwnypack.codec

Contains various methods to transcode strings.

- `xor` performs a cyclic *exclusive or* operation on a string.
- `rot13` performs rot13 'encryption' on a string.
- `caesar` performs caesar cipher encryption on a string.
- `enhex`/`dehex` convert to/from hex.
- `enb64`/`deb64` convert to/from base64.
- `frequency` performs frequency analysis on a string.

## Contributors

Just me for now. If you want to contribute, feel free to fork & create a pull request on GitHub.

## License

*pwnypack* is distributed under the MIT license.
