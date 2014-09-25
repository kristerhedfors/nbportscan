#!/bin/sh
#
# Copyright(c) 2014 - Krister Hedfors
#
# Usage:
# $ bash py_compact_exec.sh myprog.py > mycmdline.txt
#

READ_REMOVE_COMMENTS="''.join(filter(lambda r: r[0] != '#', open('$1')))" 
COMPRESS_AND_BASE64="__import__('zlib').compress($READ_REMOVE_COMMENTS).encode('base64').replace('\\n', '')"
RESULT=`python -c "print $COMPRESS_AND_BASE64"` 

echo "python -c \"exec __import__('zlib').decompress('$RESULT'.decode('base64'))\""

