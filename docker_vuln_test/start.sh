#!/bin/bash

/usr/sbin/sshd -D
apachectl -k start
tail -f /dev/null
