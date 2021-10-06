#!/bin/bash

# Initialize the user configurations when the box is built
function init_user_configs() {
  log_function $@
  local box_name=$1

  # If we have a centrally stored shadow file, use it
  get_stored_users

  # Allow wheel group users to sudo, without a password
  setup_sudoers
  setup_box_groups

  setup_sysadmin_users
  setup_cron_user_refresh
}

# Setup a cron.d entry to rerun user setup every 15 minutes
function setup_cron_user_refresh() {
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

# Save the current /etc/shadow password file to the box store, as a backup.
# This should be called after any user updates and periodically
function store_users() {
  log_function $@
  save_to_box_store /etc/shadow
  save_to_box_store /etc/passwd
}

# Restore the /etc/shadow password file from the box store. Typically
# used when a box is created.
function get_stored_users() {
  log_function $@
  get_from_box_store /etc/shadow
  chown root:root /etc/shadow
  chmod 600 /etc/shadow
  get_from_box_store /etc/passwd
  chown root:root /etc/passwd
  chmod 644 /etc/passwd
  add_status
}

# Save the current /etc/group file to the box store, as a backup.
# This should be called after any user updates and periodically
function store_groups() {
  log_function $@
  save_to_box_store /etc/group
}

# Restore the /etc/group file from the box store. Typically
# used when a box is created.
function get_stored_groups() {
  log_function $@
  get_from_box_store /etc/group
  chown root:root /etc/group
  chmod 644 /etc/group
  add_status
}

# Save the IAM user list to the box store.
# This should be called after any user updates and periodically
function store_iam_users() {
  log_function $@
  save_to_box_store ${IAM_USERS_FILE}
}

# Restore the IAM user list file from the box store.
function get_stored_iam_users() {
  log_function $@
  get_from_box_store ${IAM_USERS_FILE}
  if [ -f ${IAM_USERS_FILE} ]; then
    chown root:root ${IAM_USERS_FILE}
    chmod 644 ${IAM_USERS_FILE}
    cat ${IAM_USERS_FILE}
  else
    log INFO "No IAM users file retrieved to: ${IAM_USERS_FILE}"
  fi
}

# Refresh users from IAM
# Typically called frequently from a cron job
function refresh_users() {
  log_function $@

  setup_sysadmin_users
  if [ $? == 0 ]; then

    run_touched_admin_files
    store_users
    store_groups

  else
    log ERROR "refresh_users failed"
  fi

}

# Run admin functions based on files existing in USER_CONFIGS_DIR
# See the scripts in common/templates/all/util_scripts
function run_touched_admin_files() {
  disable_users
  if [ "$(which google-authenticator 2> /dev/null)" ]; then
    reset_google_auths
  fi
  kill_user_processes
}

# Setup the sudoers based on being a member of the wheel group
# Ensure ec2-user can not sudo
function setup_sudoers() {
  log_function $@

  rm -f /etc/sudoers.d/cloud-init
  echo '%wheel ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/wheel
  chmod 0440 /etc/sudoers.d/wheel
}

# The user configs "grouplist" file lists the OS groups to be set up on all
# servers. This function adds a group if it doesn't already exist, so it can
# safely be rerun periodically.
# The grouplist file has each groupname,gid on its own line. For example:
# fphsadmi,3000474
# fphsdata,3000476
# ...
function setup_box_groups() {
  log_function $@
  local glfile=/etc/grouplist

  # See if there is a box specific version in the templates,
  # otherwise use the root level template instead
  local group=setup_users
  init_templates ${group} ${BOX_NAME}
  if [ ! $(template_exists ${group} ${glfile}) ]; then
    init_templates ${group}
    if [ ! $(template_exists ${group} ${glfile}) ]; then
      log INFO "No /etc/grouplist for setup_users templates. Returning"
      return
    fi
  fi

  use_template setup_users ${glfile}

  if [ ! -f ${glfile} ]; then
    log INFO "No grouplist file ${glfile}"
    return
  fi

  unset IFS
  for g in $(cat "${glfile}"); do
    IFS=','
    read -a strarr <<< "${g}"
    unset IFS
    local gname="${strarr[0]}"
    local gid="${strarr[1]}"
    if [ -z $(getent group ${gname}) ]; then
      groupadd --gid ${gid} ${gname}
      log INFO "Added group ${gid} ${gname}"
    fi
  done
  unset IFS

  add_status
}

# Get sorted list of usernames from iam
function get_users_from_iam() {
  log_function $@

  local IAM_USERS_FILE=$(mktemp)
  aws iam get-group --group-name box-admins > ${IAM_USERS_FILE} 2>&1
  if [ $? != 0 ]; then
    log ERROR "Failed to get IAM users: $(cat ${IAM_USERS_FILE})"
    return 255
  fi

  cat ${IAM_USERS_FILE} | grep -E '"UserName": ".+",' | sed -E 's/.+"UserName": "(.+)",/\1/' | sort

  rm -f ${IAM_USERS_FILE}

  log INFO "Got IAM users"
}

# For each IAM user in the IAM group box-admins, setup
# (or refresh the details for) a user
# For entries in user_configs/disable or user_configs/disable-all
# disable the users
# When complete, send the results back to the box store (passwd, shadow and groups)
# and run admin actions
function setup_sysadmin_users() {
  log_function $@

  groupadd -f ${ADMIN_GROUP}

  local usernames=$(get_users_from_iam)
  if [ ! "${usernames}" ]; then
    log ERROR "No users retrieved from IAM. Do not continue"
    return 1
  fi

  for un in ${usernames}; do
    setup_user "${un}"
  done

  local prev_users=$(get_stored_iam_users)
  if [ "${prev_users}" ]; then
    # If the user appeared in the old list, but not the new one
    # then it should be disabled
    for un in ${prev_users}; do
      local un_in_usernames=$(echo ${usernames} | grep "\b${un}\b")
      if [ ! "${un_in_usernames}" ]; then
        disable_user ${un}
      else
        log INFO "User present in stored IAM users file: ${un}"
      fi
    done
  else
    log INFO "Stored IAM users file was empty"
  fi

  echo ${usernames} > ${IAM_USERS_FILE}
  store_iam_users

}

# Setup, disable or replace a user, including groups
function setup_user() {
  local uname=$1

  # Set a variable indicating if the user exists
  local user_exists=$(getent passwd ${uname})

  if [ -z "${user_exists}" ]; then
    local group_exists=$(getent group ${uname})
    if [ -z "${group_exists}" ]; then
      local group_arg=""
    else
      local group_arg="-g ${uname}"
    fi

    local extra_groups=wheel
    if [ "${ADMIN_GROUP}" ]; then
      extra_groups=${extra_groups},${ADMIN_GROUP}
    fi
    adduser ${uname} ${group_arg} -G ${extra_groups}

    if [ $? == 0 ]; then
      log INFO "setup_user: Added user ${uname}"
    else
      log ERROR "setup_user: Failed adding user ${uname}"
      return 2
    fi
  fi

  # Set the password
  echo \"${pw}\" | passwd --stdin ${uname}
  # Set the number of days warning (defaults 14 but override if required)
  chage -W ${PW_EXP_WARN_DAYS} ${uname} 2>&1

}

# Disable user with supplied username
function disable_user() {
  local f=$1

  usermod -L ${f} 2>&1
  chage -E0 ${f} 2>&1
  usermod -s /sbin/nologin ${f} 2>&1
  killall -u ${f}
  log INFO "Disabled user account ${f} and killed all related processes"
}

# Disable users that appear in disable and disable-all directories
# in ${USER_CONFIGS_DIR}/disable or ${USER_CONFIGS_DIR}/disable-all
function disable_users() {
  log_function $@

  local disable=${USER_CONFIGS_DIR}/disable
  # If a user is listed in a disable directory, remove their access
  if [ -d ${disable} ] || [ -d ${disable}-all ]; then

    # Make the disable directory usable by admin scripts
    chown :${ADMIN_GROUP} "${disable}"*
    chmod 770 "${disable}"*

    for f in $(ls ${disable}*); do
      if [ "$(is_user_locked "${f}")" != 'locked' ] && [ "$(id ${f} 2> /dev/null)" ]; then
        disable_user ${f}
      fi
    done
  fi

}

# Kill all user processes for users with a file named the username in
# ${USER_CONFIGS_DIR}/kill-user-processes
# This allows the kill-user-processes script to be run by non-root users,
# entering a file in this directory to be run later, without having to
# grant full killall privileges
function kill_user_processes() {
  local killups=${USER_CONFIGS_DIR}/kill-user-processes
  mkdir -p "${killups}"
  chown :${ADMIN_GROUP} "${killups}"
  chmod 770 "${killups}"

  log INFO "Killing processes for users listed in ${killups} :" $(ls "${killups}")

  for f in $(ls "${killups}"); do
    killall -u "${f}"
    rm -f ${killups}/${f}
    log INFO "Killed processes for ${f}"
  done
}

# Follow up actions after creating a user
# Run each script in ${SETUP_DIR}/created_user
# Each function can access the ${CREATED_USER} variable
function created_user_actions() {
  local CREATED_USER=$1

  if [ ! -d ${CREATED_USERS_SCRIPTS} ]; then
    return
  fi

  log_function $@

  for f in ${CREATED_USERS_SCRIPTS}/*.sh; do
    log INFO "create_user_actions ${f} for ${CREATED_USER}"
    source ${f}
  done

  add_status
}

### Utilities

# List users that have been set up as users on the server,
# although this does not guarantee the user is not locked
# This finds all users in a group that we have specifically assigned to
# created users
function list_setup_users() {
  local groupname=${ALL_USERS_GROUP}

  awk -F':' "/^${groupname}:/"'{print $4}' /etc/group | sed 's/,/\n/'
}

# List only users that are setup and have not been locked
# (due to password retries or an admin locking the account)
function list_unlocked_users() {
  IFS='
'
  for uname in $(list_setup_users); do
    [ ! $(is_user_locked "${uname}") ] && echo $uname
  done
  IFS=' '
}

# Check if the specified user has been locked
function is_user_locked() {
  local user=$1
  if [ "$(getent shadow ${user})" ] && [ "$(passwd -S ${user} 2> /dev/null | grep locked)" ]; then
    echo locked
  fi
}

### Google 2FA

if [ "$(which google-authenticator 2> /dev/null)" ]; then
  get_source user_2fa.sh no_reload
fi
