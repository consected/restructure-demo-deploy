#!/bin/bash

BOX_NAME=restructure_demo

# Standard
set -xv
echo "Starting build box for: ${BOX_NAME}"
yum install -y git
cd /root
git clone https://github.com/consected/restructure-demo-deploy.git
source restructure-demo-deploy/server-build/setup.sh
source /root/setup/build_${BOX_NAME}.sh