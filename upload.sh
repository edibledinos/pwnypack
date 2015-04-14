#! /bin/sh

if [ -z "$1" ]; then
  echo "$0 <repository>"
  exit 1
fi

python setup.py sdist upload -r "$1"
