#!/bin/bash

docker build -t oracle .
docker run --name oracle --rm -p 443:443 -p 3434:3434 oracle ./oracle

while true; do
  docker exec oracle socat TCP-LISTEN:3434,reuseaddr,fork EXEC:\"./client\",pty
done
