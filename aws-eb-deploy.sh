#!/bin/bash

# NOTE: if you have trouble deploying the first time after moving to a new platform version, it may be because
# the required version of Ruby is not installed on the instance.
# eb ssh to the box, then:
# sudo -i
# rm /etc/elasticbeanstalk/baking_manifest/ruby_packages
# /opt/elasticbeanstalk/hooks/preinit/03_common_packages.sh
# Rerun the deployment
# Worst case scenario - run through the 03_common_packages.sh by hand

cd $(dirname $0)
SCRIPTDIR=$(pwd)

# Set GITREPO to the repository to install from and APPDIR directory name to match
GITREPO=${GITREPO:=https://github.com/consected/restructure-releases}
SETUPDIR=${SETUPDIR:=/tmp/retructure-app-install}
APPDIR=$SETUPDIR/restructure-releases

# Need to re initialize an environment or change the SSH keyfile?
INTERACTIVE_EB_INIT=${INTERACTIVE_EB_INIT:=--interactive}

# Set the AWS region
EBREGION=${EBREGION:=us-east-1}

AWS_EB_PROFILE=${AWS_EB_PROFILE:=restructureuser}
EB_KEYNAME=${EB_KEYNAME:=restructure-aws-eb}
EBAPPNAME=${EBAPPNAME:=restructure-demo}
ENVTYPE=${ENVTYPE:=dev}

export AWS_EB_PROFILE
export AWS_DEFAULT_REGION=${EBREGION}

if [ ! -z "$(command -v pyenv)" ]; then
  LOCAL_PYENV=$(pyenv local)
  echo Got pyenv: $LOCAL_PYENV
fi

function cleanup() {
  mv ~/.aws/credentials ~/.aws/credentials.safebak
  mv ~/.aws/credentials.bak ~/.aws/credentials
}

function setup_aws() {

  GOTPROFILE=$(cat ~/.aws/config ~/.aws/credentials | grep $AWS_EB_PROFILE)
  if [ -z "$GOTPROFILE" ]; then
    echo ""
    echo "========================================="
    echo You will need a 'named profile' to access AWS through the command line
    echo The following will attempt to set this up for you. If obscured credentials are offered, just hit enter to continue
    aws configure --profile $AWS_EB_PROFILE
    # aws configure
  fi

  pip install pyyaml -q
  pip install awsebcli --upgrade -q
  pip install aws-mfa-login --upgrade -q
  export PATH=~/.local/bin:$PATH
  echo AWS EB CLI version:
  eb --version
  echo ""
  echo "========================================="
  echo "Setting up EB requirements"

  if [ ! -z "$LOCAL_PYENV" ]; then
    echo "========================================="
    echo "Setting pyenv to $LOCAL_PYENV"
    pyenv local $LOCAL_PYENV
  fi

  if [ "${DEPLOY_REQUIRES_MFA}" == 'true' ]; then
    aws_mfa_login
  fi  

  echo "Initializing EB environment"
  eb init $EBAPPNAME -r $EBREGION --profile $AWS_EB_PROFILE $INTERACTIVE_EB_INIT -p "$EB_PLATFORM" -k "$EB_KEYNAME"

}

function aws_mfa_login() {

  EB_LIST=$(eb list)
  if [ "${EB_LIST}" != "$EBENV" ]; then
    echo ""
    echo "========================================="
    echo "MFA is required for AWS. Enter the AWS token for the user in profile ${AWS_EB_PROFILE}"

    ENV_AWS_ACCESS_KEY_ID=${ENV_AWS_ACCESS_KEY_ID:-AWS_ACCESS_KEY_ID}
    ENV_AWS_SECRET_ACCESS_KEY=${ENV_AWS_SECRET_ACCESS_KEY:-AWS_SECRET_ACCESS_KEY}

    read AWS_MFA_TOKEN
    unset AWS_SESSION_TOKEN
    unset AWS_SECRET_ACCESS_KEY
    unset AWS_ACCESS_KEY_ID
    export AWS_PROFILE=${AWS_EB_PROFILE}
    MFA_RES=$(aws-mfa-login --profile ${AWS_EB_PROFILE} --token ${AWS_MFA_TOKEN})
    # echo $MFA_RES
    if [ -z "${MFA_RES}" ]; then
      echo "${MFA_RES}"
      echo try again...
      aws_mfa_login
    else

      MFA_RES=$(echo "${MFA_RES}" | sed -r 's/export AWS_ACCESS_KEY_ID=/aws_access_key_id = /')
      MFA_RES=$(echo "${MFA_RES}" | sed -r 's/export AWS_SECRET_ACCESS_KEY=/aws_secret_access_key = /')
      MFA_RES=$(echo "${MFA_RES}" | sed -r 's/export AWS_SESSION_TOKEN=/aws_session_token = /')
      MFA_RES=$(echo "${MFA_RES}" | sed -r 's/unset AWS_PROFILE;//')
      MFA_RES=$(echo "${MFA_RES}" | sed -r 's/;//')

      # echo ${AWS_SESSION_TOKEN}

      trap cleanup EXIT
      mv ~/.aws/credentials ~/.aws/credentials.bak
      echo "[${AWS_EB_PROFILE}]" > ~/.aws/credentials
      echo "${MFA_RES}" >> ~/.aws/credentials
    fi
  fi
}

if [ -z "$APPSRC" ]; then
  echo ""
  echo "========================================="
  echo "Enter 1 to clone from Git, or 2 to use the previously downloaded source (${SETUPDIR})"
  echo "GITREPO is ${GITREPO}"
  echo "Enter 1 or 2"
  read APPSRC
fi


if [ "$APPSRC" == '1' ]; then

  echo ""
  echo "========================================="
  if [ -z "${APPVER}" ]; then
    echo "Enter the version to checkout (tag name, commit or branch name)"
    read APPVER
  else
    echo "Checking out version #{APPVER}"
  fi

  rm -rf $SETUPDIR
  mkdir $SETUPDIR
  cd $SETUPDIR

  echo "Git Cloning ${GITREPO} with version $APPVER to $SETUPDIR"
  git -c advice.detachedHead=false clone --single-branch --branch "${APPVER}" --depth 1 ${GITREPO}
  cd $APPDIR

  git -c advice.detachedHead=false checkout $APPVER
  SETASSETS=true
fi

if [ "$APPSRC" == '2' ]; then
  cd $APPDIR

  echo ""
  echo "========================================="
  echo "Using existing assets"
  SETASSETS=true
fi

git config --global advice.detachedHead false

if [ "$SETASSETS" != "true" ]; then
  echo "Incorrect option specified"
  exit
fi

APPVERSION=$(cat version.txt)

if [ -z "$APPVERSION" ]; then
  echo "App source code is not available or the version.txt file is missing. Try re-running with option 1"
  exit
fi

echo ""
echo "========================================="
echo "Code is in: $(pwd)"
echo "Version according to source code is: $APPVERSION"
echo "If this is correct, hit enter. Otherwise Ctrl-C to exit."
read CORRECT

echo ""
echo "========================================="
if [ -z "${EBAPPNAME}" ]; then
  echo "Select the EB app name to deploy"
  read EBAPPNAME
else
  echo "Deploying to EB app: ${EBAPPNAME}"
fi

OPTIONSDIR=$SCRIPTDIR/aws/$EBAPPNAME

echo ""
echo "========================================="
if [ -z "${ENVTYPE}" ]; then
  echo "Enter the environment name to deploy"
  echo "Configured environments are:"
  echo $(cd ${OPTIONSDIR}/; ls *-env.vars | sed -n "s/\(.\+\)-env.vars/\1/p")
  read ENVTYPE
else
  echo "Deploying to environment: ${ENVTYPE}"
fi

echo "========================================="
echo "Load common variables from $OPTIONSDIR/$ENVTYPE-env.vars"
echo

if [ ! -f "$OPTIONSDIR/$ENVTYPE-env.vars" ]; then
  echo ""
  echo "========================================="
  echo "The environment file '$OPTIONSDIR/$ENVTYPE-env.vars' does not exist. Quitting"
  echo
  exit
fi

source $OPTIONSDIR/$ENVTYPE-env.vars

if [ "$SKIP_MIGRATIONS" == 'true' ]; then
  echo "========================================="
  echo "The $ENVTYPE deployment does not migrate the database. It is essential to ensure the database has been migrated prior to deployment."
  echo "Use app-scripts/gen_schema_migrations.sh or app-scripts/migrate-aws-db.sh or the 'migrate' EB environment to run migrations."
  read -p "Once migrated, hit enter to continue" _NOENTRY
fi


echo 
echo "========================================="
echo "GPG is used to unencrypt app secrets in the file '$OPTIONSDIR/$ENVTYPE-secrets.gpg'"
echo "Enter the encryption key now."
read -s PCODE && echo $PCODE | gpg --batch --yes --passphrase-fd 0 $OPTIONSDIR/$ENVTYPE-secrets.gpg
unset PCODE

if [ -f $OPTIONSDIR/$ENVTYPE-secrets ]; then
  source $OPTIONSDIR/$ENVTYPE-secrets

  ENV_AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
  ENV_AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY

  rm $OPTIONSDIR/$ENVTYPE-secrets
else
  echo "File $OPTIONSDIR/$ENVTYPE-secrets.gpg was not unencrypted. Perhaps the GPG passcode was incorrect. Exiting..."
  exit
fi

setup_aws

#### Forcing AMI
# If you accidentally deregistered an AMI associated with an EB image it is necessary to set the configuration for a new one
# In the console you'll get a message like this when you access the environment: Unable to look up root device name for image 'ami-xxxxxx'
if [ ! -z "$FORCE_AMI" ]; then
  echo "Forcing a new AMI onto an existing environment. This will rebuild the instances. If you are sure you want to continue, hit enter. Otherwise Ctrl-C"
  read _OK
  aws elasticbeanstalk update-environment --environment-name $EBENV --option-settings Namespace=aws:autoscaling:launchconfiguration,OptionName=ImageId,Value=$FORCE_AMI
fi

echo ""
echo "========================================="
echo Making ebextensions configurations
mkdir -p $APPDIR/.ebextensions

echo Cleaning up old config files
rm $APPDIR/.ebextensions/*.config
rm $APPDIR/passenger-standalone.json

echo Configuring ebextensions
cp $OPTIONSDIR/ebextensions/*.config $APPDIR/.ebextensions/
cp $OPTIONSDIR/ebextensions/${ENVTYPE}/*.config $APPDIR/.ebextensions/

if [ "$NO_CERTIFICATE" != 'true' ]; then
  echo ""
  echo "========================================="
  echo "GPG is used to unencrypt the $ENVTYPE certs in file $OPTIONSDIR/$ENVTYPE-cert-content.gpg"
  echo "Enter the encryption key now."
  read -s PCODE && echo $PCODE | gpg --batch --yes --passphrase-fd 0 $OPTIONSDIR/$ENVTYPE-cert-content.gpg
  if [ -f $OPTIONSDIR/$ENVTYPE-cert-content ]; then
    mv $OPTIONSDIR/$ENVTYPE-cert-content $APPDIR/.ebextensions/certificates.config
  else
    echo "File $OPTIONSDIR/$ENVTYPE-cert-content.gpg was not unencrypted. Perhaps the GPG passcode was incorrect. Exiting..."
    exit
  fi
fi

# From https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/https-singleinstance-ruby.html
# Sets up the passenger server for ssl

cat > $APPDIR/passenger-standalone.json << EOF
{
  "ssl" : true,
  "ssl_port" : 443,
  "ssl_certificate" : "/etc/pki/tls/certs/server.crt",
  "ssl_certificate_key" : "/etc/pki/tls/certs/server.key"
}
EOF


if [ -z "$EBENV" ]; then
  echo "Environment information was not loaded."
  exit
fi

if [ "$ENVTYPE" != 'migrate' ]; then

  while [ "${SETUPAPP}" != 'setup' ] && [ "${SETUPAPP}" != 'env' ] && [ "${SETUPAPP}" != 'deploy' ]; do
    echo ""
    echo "========================================="
    echo "Setup the environment ($EBENV), use an existing one?, or just reset environment variables"
    echo "Enter:"
    echo "setup   to create the environment"
    echo "env     to reset environment variables then exit"
    echo "deploy  to deploy to the existing environment."
    read SETUPAPP
  done
else
  echo ""
  echo "========================================="
  echo "Migration schema MIG_PATH=${MIG_PATH}"
  echo "Is this correct? y/n"
  read migpath_ok

  if [ "${migpath_ok}" != 'y' ]; then
    echo "enter the MIG_PATH you want to use"
    read MIG_PATH
  fi

fi

if [ "$SETUPAPP" == 'env' ]; then
  ONLY_SETENV=true
fi

if [ "$SETUPAPP" == 'setup' ] || [ "$ENVTYPE" == 'migrate' ]; then

  echo ""
  echo "========================================="
  echo "Creating a $ENVTYPE environment ($EBENV), connecting to database ($DB_HOST)"
  echo

  if [ "$ENVTYPE" != 'migrate' ]; then
    echo "========================================="
    echo "Ensure that the database has been created and seeded before continuing."
    echo "Run app-scripts/ app-scripts/seed-aws-db.sh from a current installation directory"
  fi
  read -p "Hit enter to continue" _NOENTRY

  # Required because the cli can't cope with commas in eb create
  TEMP_DB_SEARCH_PATH=ml_app

  eb create $EBENV --single -pr \
    --instance_type=$SERVERSIZE \
    --vpc --vpc.id="$VPC_ID" --vpc.ec2subnets="$VPC_SUBNETS" \
    --vpc.securitygroup="$SECURITY_GROUPS" \
    -p "$EB_PLATFORM" \
    -k "$EB_KEYNAME" \
    --envvars \
    SECRET_KEY_BASE="$SECRET_KEY_BASE",FPHS_RAILS_SECRET_KEY_BASE="$SECRET_KEY_BASE",FPHS_RAILS_DEVISE_SECRET_KEY="$DEVISE_SECRET_KEY_BASE",RAILS_ENV=production,RAILS_SERVE_STATIC_FILES="$RAILS_SERVE_STATIC_FILES",RAILS_SKIP_ASSET_COMPILATION=true,FPHS_ENV_NAME="$FPHS_ENV_NAME",FPHS_POSTGRESQL_HOSTNAME="$DB_HOST",FPHS_POSTGRESQL_USERNAME="$DB_USERNAME",FPHS_POSTGRESQL_PASSWORD="$DB_PASSWORD",FPHS_POSTGRESQL_DATABASE="$DB_NAME",FPHS_POSTGRESQL_PORT="$DB_PORT",RDS_SCHEMA="$TEMP_DB_SEARCH_PATH",FPHS_POSTGRESQL_SCHEMA="$TEMP_DB_SEARCH_PATH",RAILS_SKIP_MIGRATIONS="$SKIP_MIGRATIONS",SMTP_SERVER="$SMTP_SERVER",SMTP_PORT=465,SMTP_USER_NAME="$SMTP_USER_NAME",SMTP_PASSWORD="$SMTP_PASSWORD",FPHS_FROM_EMAIL="$FROM_EMAIL",FILESTORE_CONTAINERS_DIRNAME=containers,FILESTORE_NFS_DIR=/mnt/fphsfs,FILESTORE_TEMP_UPLOADS_DIR=/tmp/uploads,FILESTORE_USE_PARENT_SUB_DIR="$FILESTORE_USE_PARENT_SUB_DIR",FPHS_X_SENDFILE_HEADER="X-Accel-Redirect",BASE_URL="$BASE_URL",SMS_SENDER_ID="$SMS_SENDER_ID",FPHS_LOAD_APP_TYPES=1,MIG_PATH="$MIG_PATH"

  eb use $EBENV

  if [ "$ENVTYPE" == 'migrate' ]; then
    echo "========================================="
    echo "Migration should have completed. Enter the environment name to terminate the migrate server if the database has been migrated OK."
    eb terminate
    exit
  fi


  echo "========================================="
  echo "Ensure the public IP address reported above is set in the appropriate passenger_startup_conf.config file"
  echo "Ensure the Route 53 record set for the internal domain $APPDOMAINNAME has been set up and points to the instance via a CNAME."
  nslookup $APPDOMAINNAME
  if [ "$?" == "1" ]; then
    echo "Domain name NOT found"
    read -p "Add the domain name to Route 53, then hit enter to continue" _NOENTRY
  else
    echo "Internal Domain name found"
  fi

else
  echo ""
  echo "========================================="
  echo Initializing the existing environment
  eb use $EBENV
fi

if [ -z "$DB_PASSWORD" ]; then

  echo "DB password not set. Make sure it is in the secrets file."
  exit
fi
if [ -z "$SMTP_PASSWORD" ]; then
  echo "SMTP password not set. Make sure it is in the secrets file"
  exit
fi

if [ -z "$DB_HOST" ]; then
  export DBCONFIG=$(pwd)/../awsdbconfig.json

  aws rds describe-db-instances --region ${EBREGION} --profile $AWS_EB_PROFILE > $DBCONFIG

  echo "Got DB details from $DBCONFIG"
  echo "Running $SCRIPTDIR/deploy-aws-get-db-config.rb to find $DB_NAME"

  DBRES=$(ruby $SCRIPTDIR/deploy-aws-get-db-config.rb)

  echo Got database details: $DBRES

  export DB_HOST="$(echo $DBRES | awk '{print $1}')"
  export DB_PORT="$(echo $DBRES | awk '{print $2}')"
fi

if [ "${SKIP_MIGRATIONS}" != 'true' ]; then
  echo ""
  echo "========================================="
  echo DB host name: $DB_HOST
  echo DB name: $DB_NAME
  echo Hit enter to confirm this is the correct DB
  read

  eb status | grep "Environment details"
  echo Hit enter to confirm the correct environment details
  read
fi

if [ -z "$RDS_HOST" ]; then

  echo ""
  echo "========================================="
  echo Setting up environment variables

  eb setenv \
    SECRET_KEY_BASE="$SECRET_KEY_BASE" \
    FPHS_RAILS_SECRET_KEY_BASE="$SECRET_KEY_BASE" \
    FPHS_RAILS_DEVISE_SECRET_KEY="$DEVISE_SECRET_KEY_BASE" \
    RAILS_ENV=production \
    RAILS_SERVE_STATIC_FILES="$RAILS_SERVE_STATIC_FILES" \
    RAILS_SKIP_ASSET_COMPILATION=true \
    FPHS_ENV_NAME="$FPHS_ENV_NAME" \
    FPHS_POSTGRESQL_HOSTNAME="$DB_HOST" \
    FPHS_POSTGRESQL_USERNAME="$DB_USERNAME" \
    FPHS_POSTGRESQL_PASSWORD="$DB_PASSWORD" \
    FPHS_POSTGRESQL_DATABASE="$DB_NAME" \
    FPHS_POSTGRESQL_PORT="$DB_PORT" \
    RDS_SCHEMA="$DB_SEARCH_PATH" \
    FPHS_POSTGRESQL_SCHEMA="$DB_SEARCH_PATH" \
    RAILS_SKIP_MIGRATIONS="$SKIP_MIGRATIONS" \
    SMTP_SERVER="$SMTP_SERVER" \
    SMTP_PORT=465 \
    SMTP_USER_NAME="$SMTP_USER_NAME" \
    SMTP_PASSWORD="$SMTP_PASSWORD" \
    FPHS_FROM_EMAIL="$FROM_EMAIL" \
    FILESTORE_CONTAINERS_DIRNAME=containers \
    FILESTORE_NFS_DIR=/mnt/fphsfs \
    FILESTORE_TEMP_UPLOADS_DIR=/tmp/uploads \
    FILESTORE_USE_PARENT_SUB_DIR="$FILESTORE_USE_PARENT_SUB_DIR" \
    FPHS_X_SENDFILE_HEADER="X-Accel-Redirect" \
    BASE_URL="$BASE_URL" \
    SMS_SENDER_ID="$SMS_SENDER_ID" \
    FPHS_LOAD_APP_TYPES="$FPHS_LOAD_APP_TYPES" \
    FPHS_2FA_AUTH_DISABLED="$FPHS_2FA_AUTH_DISABLED" \
    FPHS_PASSWORD_AGE_LIMIT="$FPHS_PASSWORD_AGE_LIMIT" \
    FPHS_PASSWORD_REMINDER_DAYS="$FPHS_PASSWORD_REMINDER_DAYS" \
    AWS_ACCESS_KEY_ID="$ENV_AWS_ACCESS_KEY_ID" \
    AWS_SECRET_ACCESS_KEY="$ENV_AWS_SECRET_ACCESS_KEY" \
    LOGIN_ISSUES_URL="$LOGIN_ISSUES_URL" \
    LOGIN_MESSAGE="$LOGIN_MESSAGE" \
    MIG_PATH="$MIG_PATH" \
    FPHS_ADMIN_EMAIL=${ADMIN_EMAIL}

fi

if [ "$ONLY_SETENV" ]; then
  echo "Environment variable setup complete. Exiting"
  exit
fi


echo ""
echo "========================================="
echo "Committing the passenger and ebextension configurations"
git -c advice.detachedHead=false add $APPDIR/passenger-standalone.json
git -c advice.detachedHead=false commit $APPDIR/passenger-standalone.json -m "Add passenger standalone config"
git -c advice.detachedHead=false add $APPDIR/.ebextensions
git -c advice.detachedHead=false commit $APPDIR/.ebextensions -m "Add ebextensions"

echo ""
echo "========================================="
echo "Waiting for ready status to start deployment"
eb_status=$(eb status | grep 'Status: Ready' | wc -l)
echo ${eb_status}
while [ "${eb_status}" != '1' ]; do
  echo "Sleeping for 10 seconds then trying again"
  sleep 10
  eb_status=$(eb status | grep 'Status: Ready' | wc -l)
  echo ${eb_status}
done

echo ""
echo "========================================="
echo "Starting deployment"

eb deploy

echo "Completed deployment"

# cleanup the certificates file
rm $APPDIR/.ebextensions/certificates.config

git config --global advice.detachedHead true


echo ""
echo "========================================="
echo "Cleanup incoming port 22 and 80 on default security groups"
echo
SGIDS=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=*AWSEBSecurityGroup*" "Name=ip-permission.from-port,Values=80" \
  --query "SecurityGroups[*].[GroupId]" \
  --output text)
for sg in ${SGIDS}; do
  aws ec2 revoke-security-group-ingress \
    --group-id ${sg} \
    --protocol tcp \
    --port 80 \
    --cidr 0.0.0.0/0
  echo "Removed port 80 from security group ${sg}"
done

SGIDS=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=*AWSEBSecurityGroup*" "Name=ip-permission.from-port,Values=22" \
  --query "SecurityGroups[*].[GroupId]" \
  --output text)
for sg in ${SGIDS}; do
  aws ec2 revoke-security-group-ingress \
    --group-id ${sg} \
    --protocol tcp \
    --port 22 \
    --cidr 0.0.0.0/0
  echo "Removed port 22 from security group ${sg}"
done

echo ""
echo "========================================="
echo "Completed"
