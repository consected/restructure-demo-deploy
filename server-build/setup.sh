#!/bin/bash

cd /root/restructure-demo-deploy
SETUP_DIR=/root/setup
mkdir -p ${SETUP_DIR}
cp -r server-build ${SETUP_DIR}
mv ${SETUP_DIR}/scripts/* ${SETUP_DIR}/

