#!/bin/bash

cd /root/restructure-demo-deploy
SETUP_DIR=/root/setup
mkdir -p ${SETUP_DIR}
\cp -fr server-build/* ${SETUP_DIR}/
mv -f ${SETUP_DIR}/scripts/* ${SETUP_DIR}/
