#!/bin/bash

docker build -t ubuntu-vuln-test -f Dockerfile .

docker run -d --privileged ubuntu-vuln-test /usr/sbin/init
