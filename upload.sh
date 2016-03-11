#! /bin/sh

if [ -z "$1" ]; then
  echo "$0 <repository>"
  exit 1
fi

python setup.py sdist bdist_wheel upload -r "$1"
