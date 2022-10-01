#!/bin/bash

docker pull twdps/certificate-init-container
export RESULT=$(docker run -it twdps/certificate-init-container:latest | grep "self-signed certificate requested with the following information")
if [[ "${RESULT}" == "" ]]; then
  echo 'Container did not log success'
  exit 1
fi
