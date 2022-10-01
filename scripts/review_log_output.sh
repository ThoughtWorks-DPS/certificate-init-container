#!/bin/bash

docker pull twdps/certificate-init-container
export RESULT=$(docker run -it twdps/certificate-init-container:latest | grep "Success: certificate and private key created")
if [[ "${RESULT}" == "" ]]; then
  echo 'Container did not log success'
  exit 1
fi
