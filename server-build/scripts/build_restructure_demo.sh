#!/bin/bash
BOX_NAME=restructure-demo
HOSTNAME=restructure.consected.com
EXTERNAL_HOSTNAME=restructure.consected.com

AWS_ACCT=012511364329
AWS_REGION=us-east-1
OSTYPE=amazonlinux2

RESTR_FS_ROOT=/efs1
RESTR_FS_DIR=restructure-demo-main
RESTR_MOUNT_ROOT=/mnt/fphsfs
RESTR_WEBAPP_USER=webapp
RESTR_EFS_ID=fs-07ddf2f2
NFS_MOUNTPOINT=${RESTR_FS_ROOT}

# Note: GPG key is stored in the AWS Secrets Manager 
# Add a secret, identified by Restr/PROD/ServerBuild/SecretsGpgPasscode with key / value
# SecretString : <GPG key>
AWS_SMID_SECRETS_PASSCODE=Restr/PROD/ServerBuild/SecretsGpgPasscode-3YUTVL

FROM_ADMIN_EMAIL=admin@consected.com
NOTIFICATION_TO_EMAIL=admin@consected.com
SERVICE_ASSETS_BUCKET=restr-service-assets
INSTALL_ASSETS_BUCKET=restructure-demo-assets

if [ "${OSTYPE}" == 'centos7' ] || [ "${OSTYPE}" == 'centos8' ]; then
  EC2USER=centos
else
  EC2USER=ec2-user
fi

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
SETUP_DIR=${SETUP_DIR:-/root/setup}

source ${SETUP_DIR}/common_functions.sh
setup_basics
add_swap 2048
get_source setup_certbot_docker.sh
setup_certbot_docker
certbot_issue_certificate ${INTERNAL_HOSTNAME} ${EXTERNAL_HOSTNAME}
get_source setup_restructure_eb.sh
setup_restructure_eb

echo "DONE!"
