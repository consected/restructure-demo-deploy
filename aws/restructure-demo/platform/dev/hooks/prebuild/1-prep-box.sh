#!/bin/bash

BOX_NAME=restructure_demo

# Standard
set -xv
echo "Starting build box for: ${BOX_NAME}"

cd /root
git clone https://github.com/consected/restructure-demo-deploy.git
source restructure-build/server-build/setup.sh
source setup/build_${BOX_NAME}.sh