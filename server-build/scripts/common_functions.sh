#!/bin/bash

SETUP_DIR=/root/setup
ENV_SOURCE=${SETUP_DIR}/env_build.sh
ASSETS_DIR=${SETUP_DIR}/assets
CREATED_USERS_SCRIPTS=${SETUP_DIR}/created_user
SB_LOGS_DIR=${SETUP_DIR}/logs
SB_LOGFILE=${SB_LOGS_DIR}/setup.log
SB_ERRORFILE=${SB_LOGS_DIR}/errors.log
GITREPOS_DIR=${SETUP_DIR}/gitrepos
TEMPLATES_DIR=${SETUP_DIR}/templates
RUN_ONE_OFFS_DIR=${SETUP_DIR}/run
STATUS_FILE=${SETUP_DIR}/status
CENTRAL_PW_DIR=/etc/central_passwords
USER_CONFIGS_DIR=/etc/user_configs
SSH_AUTH_KEYS=${USER_CONFIGS_DIR}/ssh/authorized_keys
MEMTMP=/dev/shm
LOCKFILE=${MEMTMP}/setup-common-lock
LOCKDIR=/var/lock/server-setup-dir
LOCKSLEEP=15
UTIL_SCRIPTS_DIR=/usr/sbin
ADMIN_GROUP=fphsadmi
PW_EXP_WARN_DAYS=21

export AWS_DEFAULT_REGION=${AWS_REGION}
HOSTNAMEFILE=/etc/hostname
HOSTSFILE=/etc/hosts
SWAPFILE=/swapfile
YUM_CRON_CONF=/etc/yum/yum-cron.conf
SERVER_BUILD_STARTUP=/root/setup/server-build-startup.sh
SETUP_2FA=/usr/local/bin/setup-2fa
CRON_DIR=/etc/cron.d
GIT_ASKPASS=${SETUP_DIR}/git_get_password.sh



JOURNAL_LOGGER=$(which systemd-cat)

# set -o pipefail  # trace ERR through pipes
# set -o errtrace  # trace ERR through 'time command' and other functions
# set -o nounset   ## set -u : exit the script if you try to use an uninitialised variable
# set -o errexit   ## set -e : exit the script if any statement returns a non-true return value

#
############### PUBLIC SETUP FUNCTIONS ###############
#

# setup basics
function setup_basics() {
  log_function $@
  if do_once; then
    save_env
    init_users
    set_hostname
    yum upgrade -y
    yum install -y epel-release
    yum -y update
    yum install -y nano htop unzip wget iftop psmisc yum-plugin-versionlock
    setup_rebooter
    setup_aws_ssm_agent
    setup_firewall
    setup_security_updates
    schedule_run_one_offs
    schedule_setup_reboot
  else
    handle_restart
  fi

  add_status

}

function add_util_scripts() {
  log_function $@

  init_templates util_scripts

  for script in $(ls ${TEMPLATES_DIR}/util_scripts/${UTIL_SCRIPTS_DIR}); do
    use_template util_scripts ${UTIL_SCRIPTS_DIR}/${script} no_substitution
    chmod 750 ${UTIL_SCRIPTS_DIR}/${script}
  done

  add_status
}

function save_env() {
  do_once || return
  log_function $@

  init_templates environment

  if [ -z "${BOX_NAME}" ]; then
    log ERROR "Box name not set saving environment"
    return
  fi

  BOX_NAME=${BOX_NAME} \
    HOSTNAME=${HOSTNAME} \
    EXTERNAL_HOSTNAME=${EXTERNAL_HOSTNAME} \
    INTERNAL_HOSTNAME=${INTERNAL_HOSTNAME} \
    OSTYPE=${OSTYPE} \
    AWS_SMID_SECRETS_PASSCODE=${AWS_SMID_SECRETS_PASSCODE} \
    SERVICE_ASSETS_BUCKET=${SERVICE_ASSETS_BUCKET} \
    INSTALL_ASSETS_BUCKET=${INSTALL_ASSETS_BUCKET} \
    AWS_ACCT=${AWS_ACCT} \
    SYNC_CENTRAL_PASSWORD_FILES_ONCE=${SYNC_CENTRAL_PASSWORD_FILES_ONCE} \
    use_template environment ${ENV_SOURCE}

  save_env_server_store

  add_status
}

function save_env_server_store() {
  do_once || return
  log_function $@

  if [ "${BOX_STORE}" ]; then
    echo NFS_MOUNTPOINT=${NFS_MOUNTPOINT} > ${SETUP_DIR}/env_build_server_store.sh
    echo SERVER_STORE=${SERVER_STORE} >> ${SETUP_DIR}/env_build_server_store.sh
    echo BOX_STORE=${BOX_STORE} >> ${SETUP_DIR}/env_build_server_store.sh
    mkdir -p ${BOX_STORE}
  fi

  add_status
}

# Save the file in the first argument to the box store
# By default, we only overwrite if the file is newer than that in the store
# To force overwriting with an older file, use the second argument 'any-age'
# Usage:
#   save_to_box_store /var/lib/somefile
# or:
#   save_to_box_store /var/lib/olderfile any-age
#
function save_to_box_store() {
  log_function $@

  if [ -z "$1" ]; then
    log ERROR "save_to_box_store requires path argument"
    return
  fi

  local from_path=$1
  local extra=$2

  if [ "${extra}" != 'any-age' ]; then
    local extra_arg='-u'
  fi

  if [ "${BOX_STORE}" ] && [ -s ${from_path} ]; then
    mkdir -p "${BOX_STORE}"/$(dirname ${from_path})
    \cp -f --dereference ${extra_arg} ${from_path} "${BOX_STORE}"/${from_path}
  fi

}

function get_from_box_store() {
  log_function $@

  if [ -z "$1" ]; then
    log ERROR "get_from_box_store requires path argument"
    return
  fi

  local from_path=$1
  local store_path="${BOX_STORE}"/${from_path}

  if [ "${BOX_STORE}" ] && [ -s ${store_path} ]; then
    mkdir -p $(dirname ${from_path})
    \cp -f --preserve=all ${store_path} ${from_path}
  fi

}

function set_box_store() {
  log_function $@

  if mountpoint -q ${NFS_MOUNTPOINT}; then
    SERVER_STORE=${NFS_MOUNTPOINT}/server-store
    BOX_STORE=${SERVER_STORE}/${BOX_NAME}
  fi
}

function handle_restart() {
  log_function $@
  yum upgrade -y
  systemctl start amazon-ssm-agent
  add_status

}

#
############### SYSTEM CONFIGURATION UTILITIES ###############
#

function setup_rebooter() {

  do_once || return
  log_function $@

  init_templates rebooter
  echo "#!/bin/bash" > ${SERVER_BUILD_STARTUP}
  echo "/bin/bash -c 'source ${SCRIPTNAME}' ; exit 0" >> ${SERVER_BUILD_STARTUP}
  chmod 700 ${SERVER_BUILD_STARTUP}

  use_template rebooter /usr/lib/systemd/system/server-build-startup.service
  systemctl enable server-build-startup
  add_status

}

# add swap or recreate it if there was a swap of a different size
# add_swap <swap size in k>
function add_swap() {

  local swap_size=$1

  # If a swap is in place, check if the new size requested is different
  if [ "$(swapon -s)" ]; then
    do_once "${FUNCNAME[0]} ${swap_size}" || return
  fi

  log_function $@
  # This size swap was not the latest in the status file

  if [ -f ${SWAPFILE} ]; then
    # But there was a swapfile, so swapoff just in case
    swapoff ${SWAPFILE}
  fi

  # Create (or recreate with a new size) the swapfile
  dd if=/dev/zero of=${SWAPFILE} bs=1024 count=${swap_size}k
  chown root:root ${SWAPFILE}
  chmod 0600 ${SWAPFILE}
  mkswap ${SWAPFILE}
  swapon ${SWAPFILE}

  add_status "${FUNCNAME[0]} ${swap_size}"

}

# Add sudo user with username as first arg
function add_sudo_user() {
  log_function $@
  local new_username=$1
  DEF_PW=$(ec2-metadata -i | cut -d " " -f 2)
  adduser ${new_username}
  # Previously we set the init password to be the instance id. Now we rely on the user_configs/passwords/init file
  # usermod -p $(openssl passwd -1 "${DEF_PW}") ${new_username}
  # passwd --expire ${new_username}
  usermod -aG wheel ${new_username}
}

# Setup users and remove default user
function init_users() {

  do_once || return
  log_function $@

  get_source user_functions.sh
  init_user_configs ${BOX_NAME}

  # Prevent default user login
  usermod -s /bin/false ${EC2USER}

  add_status
}

function set_hostname() {
  do_once || return

  log_function $@

  local curr_hostname=$(hostname)
  echo ${HOSTNAME} > ${HOSTNAMEFILE}
  # Set it temporarily until the next reboot
  sysctl kernel.hostname=${HOSTNAME}
  sed -i -E "s/${curr_hostname}/${HOSTNAME}/g" ${HOSTSFILE}
  systemctl daemon-reload

  add_status

}

function setup_aws_ssm_agent() {
  log_function $@
  if do_once; then
    if package_installed "amazon-ssm-agent"; then
      log INFO "amazon-ssm-agent already installed"
    else
      log INFO "installing amazon-ssm-agent"
      if [ "${OSTYPE}" == 'centos7' ]; then
        yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
      fi
      if [ "${OSTYPE}" == 'centos8' ]; then
        yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
      fi

      systemctl start amazon-ssm-agent
      systemctl enable amazon-ssm-agent

      # Prevent ssm-user sudo
      echo "#User rules for ssm-user" > /etc/sudoers.d/ssm-agent-users

      local agent_not_running=$(systemctl is-active amazon-ssm-agent | grep 'inactive')
      if [ ! -z "${agent_not_running}" ]; then
        log ERROR "Failed to start SSM Agent"
      else
        log INFO "SSM Agent installed and running"
        add_status
      fi
    fi
  else
    systemctl restart amazon-ssm-agent
  fi
}

function setup_firewall() {
  log_function $@
  if do_once; then

    if [ "${OSTYPE}" == 'centos7' ] || [ "${OSTYPE}" == 'centos8' ]; then
      systemctl stop firewalld
      systemctl disable firewalld
      systemctl mask --now firewalld
      yum install -y iptables-services
    fi
    if [ "${OSTYPE}" == 'amazonlinux2' ]; then
      yum install -y iptables-services
    fi

    init_templates iptables ${BOX_NAME}
    use_template iptables /etc/sysconfig/iptables
    systemctl start iptables
    systemctl start ip6tables
    systemctl enable iptables
    systemctl enable ip6tables

    add_status
  else
    # Reconfigure and restart
    init_templates iptables ${BOX_NAME}
    use_template iptables /etc/sysconfig/iptables
    systemctl restart iptables
  fi

}

function setup_security_updates() {
  do_once || return
  log_function $@
  if [ "${OSTYPE}" == 'centos7' ] || [ "${OSTYPE}" == 'centos8' ]; then

    yum -y install yum-cron
    systemctl start yum-cron
    systemctl enable yum-cron
    sed -i -E 's/^update_cmd =.+/update_cmd = security/g' ${YUM_CRON_CONF}
    sed -i -E 's/^update_messages =.+/update_messages = yes/g' ${YUM_CRON_CONF}
    sed -i -E 's/^download_updates =.+/download_updates = yes/g' ${YUM_CRON_CONF}
    sed -i -E 's/^apply_updates =.+/apply_updates = yes/g' ${YUM_CRON_CONF}
    sed -i -E 's/^emit_via =.+/emit_via = email/g' ${YUM_CRON_CONF}
    sed -i -E "s/^email_from =.+/email_from = root@${HOSTNAME}/g" ${YUM_CRON_CONF}
    sed -i -E "s/^email_to =.+/email_to = ${ADMIN_EMAIL}/g" ${YUM_CRON_CONF}
    add_status
    systemctl restart yum-cron

  else

    log INFO "${FUNCNAME[0]}($@) - Doing nothing, since this is not a Centos box"
  fi

}

# For example "America/New_York"
function set_server_timezone() {
  log_function $@
  timedatectl set-timezone $1
}

function run_admin_actions() {
  reset_google_auths
  kill_user_processes
}



function cleanup_rpm_db() {
  log INFO "RPM DB requires cleanup"
  mv -f /var/lib/rpm/__db* /tmp/
  rpm --rebuilddb
  yum clean all
}

#
############### ASSETS, TEMPLATES AND SECRETS ###############
#

# download and source script from S3
function get_source() {
  log_function $@
  local script_file=$1
  mkdir -p ${SETUP_DIR}
  cd ${SETUP_DIR}
  # aws s3 cp --only-show-errors s3://${SERVICE_ASSETS_BUCKET}/scripts/${script_file} ${script_file}
  source ${script_file}
}

# download an asset
function download_asset() {
  log_function $@
  local asset_file=$1
  mkdir -p ${ASSETS_DIR}
  cd ${ASSETS_DIR}
  aws s3 cp --only-show-errors s3://${INSTALL_ASSETS_BUCKET}/${asset_file} ${asset_file}
}

# initialize the secrets for a box, using the private passcode from the secrets manager
# init_secrets <box_name>
function init_secrets() {
  log_function $@
  local box_name=$1
  local secrets_file_gpg=$(mktemp ${MEMTMP}/setup-file-XXXXXXXXXX)
  local secrets_file=$(mktemp ${MEMTMP}/setup-file-XXXXXXXXXX)
  local secrets_file_new=$(mktemp ${MEMTMP}/setup-file-XXXXXXXXXX)
  local secrets_key_file=$(mktemp ${MEMTMP}/setup-file-XXXXXXXXXX)

  # Get the encrypted secrets
  # aws s3 cp --only-show-errors s3://${SERVICE_ASSETS_BUCKET}/secrets/${box_name}.gpg ${secrets_file_gpg}
  cp ${SETUP_DIR}/secrets/${box_name}.gpg ${secrets_file_gpg}

  # Get and parse the GPG passcode
  aws secretsmanager get-secret-value \
    --secret-id "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCT}:secret:${AWS_SMID_SECRETS_PASSCODE}" \
    --region ${AWS_REGION} \
    > ${secrets_key_file}

  local secrets_key=$(grep SecretString ${secrets_key_file} | sed -r 's/.+\\".+\\":\\"(.+)\\"}",/\1/')

  # Decrypt the secrets and source them
  gpg --decrypt --batch --passphrase ${secrets_key} < ${secrets_file_gpg} > ${secrets_file} 2>&1

  cat ${secrets_file} | grep '=' | sed 's/^/export /' >> ${secrets_file_new}

  source ${secrets_file_new}

  # Cleanup
  rm -f ${secrets_file} ${secrets_file_gpg} ${secrets_key_file} ${secrets_file_new}

}

# initialize the secrets for a box, using the private passcode from the secrets manager
# init_secrets <box_name>
function init_secrets_as_file() {
  log_function $@ > /dev/null
  local box_name=$1
  local secrets_file_gpg=$(mktemp ${MEMTMP}/setup-file-XXXXXXXXXX)
  local secrets_file=$(mktemp ${MEMTMP}/setup-file-XXXXXXXXXX)
  local secrets_key_file=$(mktemp ${MEMTMP}/setup-file-XXXXXXXXXX)

  # Get the encrypted secrets
  # aws s3 cp --only-show-errors s3://${SERVICE_ASSETS_BUCKET}/secrets/${box_name}.gpg ${secrets_file_gpg} > /dev/null
  cp ${SETUP_DIR}/secrets/${box_name}.gpg ${secrets_file_gpg}

  # Get and parse the GPG passcode
  aws secretsmanager get-secret-value \
    --secret-id "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCT}:secret:${AWS_SMID_SECRETS_PASSCODE}" \
    --region ${AWS_REGION} \
    > ${secrets_key_file}

  local secrets_key=$(grep SecretString ${secrets_key_file} | sed -r 's/.+\\".+\\":\\"(.+)\\"}",/\1/')

  # Decrypt the secrets and source them
  gpg --decrypt --batch --passphrase ${secrets_key} < ${secrets_file_gpg} > ${secrets_file} 2>&1

  # Cleanup
  rm -f ${secrets_file_gpg} ${secrets_key_file} > /dev/null

  echo "${secrets_file}"
}

function init_account_secrets() {
  init_secrets common-${AWS_ACCT}
}

function schedule_run_one_offs() {
  log_function $@
  init_templates environment
  box_name=${BOX_NAME} SERVICE_ASSETS_BUCKET=${SERVICE_ASSETS_BUCKET} use_template environment ${CRON_DIR}/run_one_offs
}

function schedule_setup_reboot() {
  log_function $@
  init_templates environment
  box_name=${BOX_NAME} SERVICE_ASSETS_BUCKET=${SERVICE_ASSETS_BUCKET} use_template environment ${CRON_DIR}/setup_reboot
}

# Run the one off scripts in the run/all and run/<box> directories
function run_one_offs() {
  log_function $@

  if [ -z "${BOX_NAME}" ]; then
    log ERROR "BOX_NAME not set"
    return
  fi

  aws s3 sync --only-show-errors s3://${SERVICE_ASSETS_BUCKET}/run/all/ ${RUN_ONE_OFFS_DIR}/all/
  aws s3 sync --only-show-errors s3://${SERVICE_ASSETS_BUCKET}/run/${BOX_NAME}/ ${RUN_ONE_OFFS_DIR}/${BOX_NAME}/

  cd "${RUN_ONE_OFFS_DIR}"
  for f in all/*.sh ${BOX_NAME}/*.sh; do
    cd "${RUN_ONE_OFFS_DIR}"
    if [ -f "${f}" ]; then
      local ro_status_name="run_one_offs//${f}"
      local ro_status="$(done_status "${ro_status_name}")"
      if [ 0 = "${ro_status}" ]; then
        log INFO "${ro_status_name}"
        source "${f}"
        add_status "${ro_status_name}"
      fi
    fi
  done

  cd "${SETUP_DIR}"

}

# initialize templates for a group, and an optional box
# init_templates <groups> <optional box>
function init_templates() {
  log_function $@
  local group=$1
  local box=$2

  if [ -z "${box}" ]; then
    box=all
  fi

  rm -rf ${TEMPLATES_DIR}
  mkdir -p ${TEMPLATES_DIR}
  # aws s3 cp s3://${SERVICE_ASSETS_BUCKET}/templates/${box}/${group}/ ${TEMPLATES_DIR}/${group}/ --recursive
  cp -r ${SETUP_DIR}/box_templates/${box}/${group}/ ${TEMPLATES_DIR}/${group}/ 
}

# use a template to make a server file
function use_template() {
  local group=$1
  local template=$2
  local no_substitution=$3
  log_function $@
  if [ -z ${template} ]; then
    log ERROR "group and / or template not specified"
    return 1
  fi
  mkdir -p $(dirname ${template})
  if [ -z "${no_substitution}" ]; then
    SB_ENV='$' envsubst < "${TEMPLATES_DIR}/${group}/${template}" > ${template}
  else
    rm -f ${template}
    cp "${TEMPLATES_DIR}/${group}/${template}" ${template}
  fi
  log INFO "${group} template created: ${template}"
}

function use_templates_matching() {
  log_function $@

  if [ -z "$2" ]; then
    log ERROR "use_templates_matching needs at least two arguments"
    return
  fi

  local group=$1
  local template_match=$2

  if [ -d "${TEMPLATES_DIR}/${group}/${template_match}" ]; then
    for f in $(ls "${TEMPLATES_DIR}/${group}/${template_match}"); do
      use_template ${group} ${CRON_DIR}/${f}
    done
  fi

  add_status
}

# Deploy a directory as a subdirectory inside an existing directory
# Optionally specify a user:group to set on all deployed files and directories
#   deploy_dir_into redcap_pull /FPHS/auto-services fphsetl <optional: delete>
# Will add the directory redcap_pull inside auto-services
# If option delete argument is added, the destination will have files and directories deleted
# that are not in the source. Beware! This is recursive and should only be used on complete trees
# with no other dependencies below them
function deploy_dir_into() {
  log_function $@

  if [ -z "$2" ]; then
    log ERROR "deploy_dir_into needs at least two arguments"
    return
  fi

  local source_dir=$1
  local dest_dir=$2
  local set_user_group=$3
  local extras=''

  if [ "$4" == 'delete' ]; then
    local extras='--delete'
  fi

  if [ "${source_dir: -1}" == '/' ] || [ "${source_dir: -1}" == '*' ]; then
    log ERROR "source_dir must not end in a / or *"
    return
  fi

  rsync -rvh ${extras} --exclude={tmp,exports,tk,log,env_override.sh,.gitignore,.pg*,files} ${source_dir} ${dest_dir}

  if [ "${set_user_group}" ]; then
    chown --recursive ${set_user_group} ${dest_dir}/${source_dir}
  fi

  add_status
}

function template_exists() {
  local group=$1
  local template_path=$2
  if [ -f ${TEMPLATES_DIR}/${group}/${template_path} ]; then
    echo 'exists'
  else
    return
  fi
}

function git_setup_password() {
  init_account_secrets
  echo '#!/bin/bash' > ${GIT_ASKPASS}
  echo 'exec echo "$GIT_PASSWORD"' >> ${GIT_ASKPASS}
  chmod 700 ${GIT_ASKPASS}
}

function git_clone_or_pull() {
  log_function $@

  local repo_name=$1
  local repo_url=$2

  local GITCMD=git

  if [ -d /opt/anaconda/bin ]; then
    local GITCMD=/opt/anaconda/bin/git
  fi

  if [ "$(which conda)" ]; then
    conda activate base
  fi

  mkdir -p ${GITREPOS_DIR}
  cd ${GITREPOS_DIR}

  git_setup_password
  export GIT_ASKPASS
  export GIT_PASSWORD

  if [ -d ${repo_name}/.git ]; then
    log INFO "Pulling existing git repo ${repo_name}"
    cd ${repo_name}
    ${GITCMD} pull
  else
    log INFO "Cloning new git repo ${repo_name}"
    ${GITCMD} clone ${repo_url}
    cd ${repo_name}
  fi

  add_status
}

# Setup a cron.d entry to rerun user setup every 15 minutes
function setup_user_refresh() {
  log_function $@
  local group=setup_users
  local template_path=${CRON_DIR}/refreshusers
  # See if there is a box specific version
  init_templates ${group} ${BOX_NAME}
  if [ ! $(template_exists ${group} ${template_path}) ]; then
    init_templates ${group}
  fi
  box_name=${BOX_NAME} SERVICE_ASSETS_BUCKET=${SERVICE_ASSETS_BUCKET} user_base_dirs=${USER_BASE_DIRS} use_template setup_users ${template_path}

}

function setup_mailx() {
  do_once || return
  log_function $@
  yum install -y mailx || echo 'already installed mailx'
  init_account_secrets
  init_templates environment
  smtp_username=${smtp_username} smtp_password=${smtp_password} use_template environment /root/.mailrc
  add_status
}

#
############### STARTUP, SHUTDOWN AND LOGGING ###############
#

# Add the status for the current function to the status log
# If no argument is provided, the function name $FUNC_NAME of the
# caller is used.
# If an argument is supplied, that is used instead.
function add_status() {
  if [ -z "$1" ]; then
    local func="${FUNCNAME[1]}"
  else
    local func=$1
  fi
  log INFO "${func} - DONE"

  echo "${func}" >> ${STATUS_FILE}
}

# Check if the status file has marked this task as done..
# Specifically, Check if the latest entry in the status file matching the first attribute
# matches all attributes in the entry.
# For example:
#   done_status add_swap 1024
# will only return done if the latest entry is 'add_swap 1024', not
# if there is a later entry 'add_swap 2048' or just 'add_swap'
function done_status() {

  if [ -z "$1" ]; then
    local base="${FUNCNAME[1]}"
    local fullargs=${base}
  else
    local base="$1"
    local fullargs="$@"
  fi

  local got_item="$(grep "${base}" ${STATUS_FILE} | tail -n 1)"

  if [ "${got_item}" == "$fullargs" ]; then
    echo 1
  else
    echo 0
  fi
}

# Return (null) if already done, and 1 if not done, allowing each function to start with
#  do_once || return
# By default it uses the $FUNCNAME of the caller with no arguments to check the status
# This can be overridden by calling with a single string argument, for example, to check
# the function name with all arguments
#  do_once "${FUNCNAME[0]} $@" || return
function do_once() {

  if [ "${DO_ONCE_AGAIN}" == 'yes' ]; then
    echo 'doing once again'
    return
  fi

  if [ -z "$1" ]; then
    local status="${FUNCNAME[1]}"
  else
    local status="$1"
  fi

  if [ 1 == "$(done_status "${status}")" ]; then
    log INFO "${status} - Already done."
    return
  else
    echo "not done yet"
    return
  fi
}

function service_enabled() {
  systemctl is-enabled $1 | grep 'enabled' 2>&1
}

function service_not_running() {
  systemctl is-active $1 | grep 'inactive'
}

function package_installed() {
  yum -C list installed $1
}

function setup_logs() {
  do_once || return
  log_function $@

  mkdir -p ${SB_LOGS_DIR}
  # Setup SELinux to allow access to setup logs just like /var/log
  which chcon 2> /dev/null && chcon --reference /var/log ${SB_LOGS_DIR}
  ln -s /root/setup/logs /var/log/server-build
  touch ${STATUS_FILE}

  add_status
}

function lock_task_exists() {
  local lockpid=$(cat ${LOCKFILE})
  ps p ${lockpid} -o pid | grep ${lockpid}
}

# Lock the process to ensure only one can run.
# We run the actual processing inside the flock process, by calling flock with the script's command
# line, only if the current script's parent is not already flock.
# The lock file is always named server-setup, and we only wait 120 seconds to the lock,
# otherwise flock exits without running the script.
function lock_script() {

  mkdir ${LOCKDIR} &> /dev/null
  while [ $? != 0 ]; do
    local lockpid=$(cat ${LOCKFILE})

    log INFO "Waiting for a lock. Running task: ${lockpid}"

    if [ ! "$(lock_task_exists)" ]; then
      log INFO "The lock task no longer exists: ${lockpid}. Unlocking forcefully"
      unlock_script
    else
      sleep ${LOCKSLEEP}
    fi
    mkdir ${LOCKDIR} &> /dev/null
  done

  # This is a failsafe
  log INFO "Running as: $(ps p $$)"
  if [ -f ${LOCKFILE} ]; then
    local lockpid=$(cat ${LOCKFILE})
    log ERROR "The lockfile ${LOCKFILE} is present. Not continuing. Running task: $(ps p ${lockpid})."
    exit
  else
    echo $$ > ${LOCKFILE}
    log INFO "LOCKED with lockfile ${LOCKFILE}. Run 'unlock_script' to unlock."
  fi

}

function unlock_script() {
  local lockpid=$(cat ${LOCKFILE})
  local force=$1

  if [ "${lockpid}" == "$$" ] || [ "${force}" == 'force' ] || [ ! "$(lock_task_exists)" ]; then
    rm -f ${LOCKFILE}
    rm -f ${MEMTMP}/setup-key-*
    rmdir ${LOCKDIR} &> /dev/null
    log INFO "Unlocked script: ${lockpid} == $$"
  else
    log INFO "Not unlocking - we do not own the lockfile: ${lockpid} != $$"
  fi
}

function on_start() {
  SCRIPTNAME="$(basename "$0")"
  setup_logs

  # Lock to prevent crons messing up setup
  lock_script

  source_env_builds
  os_specific_setup
  set_box_store
  essential_setup
  # Check RPM DB and cleanup if necessary
  yum list installed -C > /dev/null || cleanup_rpm_db

  if [ "${SCRIPTNAME}" ]; then
    exec 2> "${SB_ERRORFILE}"
  fi

  trap on_exit EXIT
  log INFO "##################################"
  log INFO "Starting common_functions"
}

function on_exit() {
  trap - EXIT
  unlock_script
  check_and_notify_errors

  log INFO "Exiting common_functions"
  log INFO "##################################"
  if [ "${SETUP_REBOOT_ON_EXIT}" == true ]; then
    log INFO "##################################"
    log INFO "Rebooting"
    log INFO "##################################"
    reboot now
  fi
  exec 2>&1
  echo 0
}

function source_env_builds() {
  source ${ENV_SOURCE}
  if [ -f ${SETUP_DIR}/env_build_*.sh ]; then
    for f in $(ls ${SETUP_DIR}/env_build_*.sh); do
      source ${f}
    done
  fi
}

function setup_chrony_for_ntp() {
  log_function $@

  if [ "${OSTYPE}" == 'centos7' ] || [ "${OSTYPE}" == 'centos8' ]; then
    yum install -y chrony || echo 'already installed ntp'
    if [ -z "$(grep '169.254.169.123' /etc/chrony.conf)" ]; then
      # Add the internally accessibly NTP server to the chrony configuration
      echo 'server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4' >> /etc/chrony.conf
    fi
    systemctl restart chronyd
    chkconfig chronyd on
  fi
  timedatectl

}

function essential_setup() {
  do_once || return
  log_function $@

  setup_mailx
  setup_chrony_for_ntp

  yum install -y gettext || echo 'already installed gettext for envsubst'
  yum install -y htop iotop || echo 'already installed htop'

  if [ ! -f "${ENV_SOURCE}" ]; then
    save_env
  fi

  add_util_scripts

  add_status

}

function send_notification_email() {
  log INFO "Sending notification email"
  local subject=$1
  local msg=$2
  aws ses send-email --from ${FROM_ADMIN_EMAIL} --to ${NOTIFICATION_TO_EMAIL} --subject "${subject}" --text "${msg}"
}

# Check for logged errors, notify by email
function check_and_notify_errors() {
  if [ -f ${SB_ERRORFILE} ] && [ ! -z "$(grep -v SETUPLOGENTRY ${SB_ERRORFILE})" ]; then
    send_notification_email "Server Setup Failure" "$(date +%m%d%Y) ${SCRIPTNAME} - failures recorded on host $(hostname) (${BOX_NAME})... check ${SB_LOGFILE}"
    mv -f ${SB_ERRORFILE} "${SB_ERRORFILE}-$(date +%Y%m%d%H%M%S)"
  fi
  return 1
}

function log() {
  local LEVEL=$1
  local MSG=$2
  local FULLMSG="$(date +%Y%m%d%H%M%S) ($$) - ${SCRIPTNAME} - ${LEVEL}: ${MSG}"

  echo ${FULLMSG} >> ${SB_LOGFILE}
  if [ -z "${SCRIPTNAME}" ]; then
    echo ${FULLMSG}
  fi

  echo "SETUPLOGENTRY ${FULLMSG}" >> "${SB_ERRORFILE}"

  if [ "${LEVEL}" == 'ERROR' ] || [ "${LEVEL}" == 'WARNING' ]; then
    echo ${FULLMSG} >> ${SB_ERRORFILE}
  fi

  if [ "${JOURNAL_LOGGER}" ]; then

    if [ "${LEVEL}" == 'ERROR' ]; then
      local jlevel=err
    elif [ "${LEVEL}" == 'WARNING' ]; then
      local jlevel=warning
    elif [ "${LEVEL}" == 'INFO' ]; then
      local jlevel=info
    else
      local jlevel=notice
    fi

    echo "${LEVEL} - ${MSG}" | systemd-cat -p "${jlevel}" -t "serversetup"
  fi

  return 1
}

# Log the calling function name, and an arbitrary number of arguments from the
# caller. For example:
#   log_function $@
# which easily passes all of the callers arguments to be logged
function log_function() {
  local ARGS="$@"
  local ARGS=$(
    IFS=$'\n'
    echo "${ARGS[*]}"
  )
  log INFO "${FUNCNAME[1]}(${ARGS})"
}

function os_specific_setup() {
  # OS specific setups
  if [ "${OSTYPE}" == 'amazonlinux1' ]; then
    function systemctl() {
      log_function $@
      if [ "$1" == 'is-active' ]; then
        if [ -z "$(service $2 status | grep "is stopped")" ]; then
          echo "$2 active"
        else
          echo "$2 inactive"
        fi
      elif [ "$1" == 'is-enabled' ]; then
        if [ -z "$(service --status-all | grep $2)" ]; then
          echo "$2 active"
        else
          echo "$2 inactive"
        fi
      else
        service $2 $1
      fi
    }
  fi
}

#
############### SETUP THE SCRIPT ###############
#
on_start
