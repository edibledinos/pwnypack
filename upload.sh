#! /bin/sh

if [ -z "$1" ]; then
  echo "$0 <repository>"
  exit 1
fi

pandoc -f markdown_github -t rst -o README.rst README.md || exit 1
python setup.py sdist upload -r "$1"
rm README.rst
