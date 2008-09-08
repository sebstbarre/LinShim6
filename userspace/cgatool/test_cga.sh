#!/bin/bash

a=`./cgatool -g -D $srcdir/rfc_example.params -s 1 -p fe80:: -o /dev/null`

if test "x$a" = "xfe80::3c4a:5bf6:ffb4:ca6c"; then
    exit 0
else
    exit -1
fi
