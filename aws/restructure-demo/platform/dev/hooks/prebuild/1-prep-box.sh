#!/bin/bash

BOX_NAME=restructure_demo

# Standard
set -xv
echo "Starting build box for: ${BOX_NAME}"

yum install -y git
while [ $? != 0 ]; do
  sleep 10
  yum install -y git
done

cd /root
rm -rf restructure-demo-deploy

git clone https://github.com/consected/restructure-demo-deploy.git
while [ $? != 0 ]; do
  sleep 30
  git clone https://github.com/consected/restructure-demo-deploy.git
done
source restructure-demo-deploy/server-build/setup.sh
source /root/setup/build_${BOX_NAME}.sh
