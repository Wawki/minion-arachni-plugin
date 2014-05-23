#!/bin/bash

set -x

# This script expects an active virtualenv

if [ -z "$VIRTUAL_ENV" ]; then
    echo "abort: no virtual environment active"
    exit 1
fi

# This scripts expects to find nmap on the path

# This check might not be necessary.
if [ ! `which arachni` ]; then
	echo "abort: no arachni found on your path"
	exit 1
fi

case $1 in
    develop)
        python setup.py develop
        ;;
esac
