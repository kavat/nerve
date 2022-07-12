#!/bin/sh

container=$(docker run -d --privileged -p 8080:8080 nerve)
docker exec -it $container /bin/bash
