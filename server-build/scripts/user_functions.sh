#!/bin/bash

function init_user_configs() {
  log_function $@
  local box_name=$1
  rm -rf ${USER_CONFIGS_DIR}
  mkdir -p ${USER_CONFIGS_DIR}

  aws s3 cp --only-show-errors s3://${SERVICE_ASSETS_BUCKET}/user_configs/${box_name}/ ${USER_CONFIGS_DIR}/ --recursive

  setup_sudoers
  setup_users
  setup_ssh_keys
  disable_root_login_ssh
  setup_user_refresh
  # If we have a centrally stored shadow file, use it
  shadow_get_user_db
}


function shadow_save_user_db() {
  log_function $@
  save_to_box_store /etc/shadow
}

function shadow_get_user_db() {
  log_function $@

  get_from_box_store /etc/shadow

  add_status
}

# Refresh users from S3 configurations
# Typically called from cron job
# Call with noreplace as the first argument if desired to
# pass this to setup_users
function refresh_users() {
  log_function $@

  local noreplace=$1

  # Before using the uploaded configurations, handle any existing
  # request, etc in the user configurations directories
  reset_google_auths

  # Now go ahead and pull the new configurations
  rm -rf ${USER_CONFIGS_DIR}_tmp
  mkdir -p ${USER_CONFIGS_DIR}_tmp
  aws s3 cp --only-show-errors s3://${SERVICE_ASSETS_BUCKET}/user_configs/${BOX_NAME}/ ${USER_CONFIGS_DIR}_tmp/ --recursive

  if [ ! -z "$(ls ${USER_CONFIGS_DIR}_tmp)" ]; then
    rm -rf ${USER_CONFIGS_DIR}
    mv ${USER_CONFIGS_DIR}_tmp ${USER_CONFIGS_DIR}

    setup_users ${noreplace}
    shadow_save_user_db
  else
    log ERROR "refresh_users failed to get the user_configs/${BOX_NAME} from s3"
  fi

}

# Setup the sudoers based on being a member of the wheel group
# Ensure ec2-user can not sudo
function setup_sudoers() {
  log_function $@

  rm -f /etc/sudoers.d/cloud-init
  echo '%wheel ALL=(ALL) ALL' > /etc/sudoers.d/wheel
  chmod 0440 /etc/sudoers.d/wheel
}

function setup_grouplist() {
  log_function $@
  local glfile=${USER_CONFIGS_DIR}/grouplist

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

function list_setup_users() {
  local pwdir=${USER_CONFIGS_DIR}/passwords
  unset IFS

  for u in $(ls ${pwdir}); do
    IFS=','
    read -a strarr <<< "$u"
    unset IFS
    local un="${strarr[0]}"
    echo ${un}
  done
  unset IFS
}

function list_unlocked_users() {
  IFS='
'
  for uname in $(list_setup_users); do
    [ ! $(is_user_locked "${uname}") ] && echo $uname
  done
  IFS=' '
}

function is_user_locked() {
  local user=$1
  if [ "$(getent shadow ${user})" ] && [ "$(passwd -S ${user} 2> /dev/null | grep locked)" ]; then
    echo locked
  fi
}

# Get the central password for the user, if one exists.
# If the central password is newer, then force an update of the user
# entry in the shadow file.
# If the user has just been set up, then the password may not be set yet,
# so just add the entry to the shadow file
function update_shadow_with_central_password() {

  local uname=$1
  if [ -z "${uname}" ]; then
    log ERROR "update_shadow_with_central_password requires username as first argument"
    return 1
  fi
  local central_pw_file=$(get_central_password_file ${uname})

  if [ -z "${central_pw_file}" ]; then
    log WARNING "No central password file was returned for ${uname}"
  else

    # Get the centrally configured password file content
    local configpw=$(cat "${central_pw_file}")
    # Get the last updated date for the centrally configured password
    local configpwdate=$(echo ${configpw} | awk -F: '{print $3}')

    # Get the last updated date for the current shadow file password. If it is not set
    # for some reason, default it to 0
    local currpw=$(getent shadow ${uname})
    local currpwdate=$(echo ${currpw} | awk -F: '{print $3}')
    currpwdate=${currpwdate:=0}

    # Get the full user/password entry from the central configuration
    if [ "${configpw}" ]; then
      # If this is not the user master server, then make the change regardless
      # Otherwise the password date must be newer and the password must have changed
      local newer_pw=
      if [ "${configpwdate}" ] && [ "${configpwdate}" -ge "${currpwdate}" ] && [ "${configpw}" != "${currpw}" ]; then
        local newer_pw=yes
      fi

      # log INFO "Shadow for ${uname}: $(getent shadow ${uname})"
      if [ -z "$(getent shadow ${uname})" ]; then
        # The shadow file is not yet set, just add the entry
        echo ${configpw} >> /etc/shadow
        log INFO "Added new entry to shadow file for ${uname} with central password"

      elif [ "$(is_user_master)" != master ] || [ "${newer_pw}" ]; then
        # The date of last password update in the central configured password file is
        # is the same as or newer than the date for the current password,
        # and the password entries do not match,
        # so update the current password

        # Escape the $ signs and backslashes
        local new_pw=$(echo ${configpw} | sed 's/\$/\\$/g' | sed 's/\//\\\//g')
        sed -i -E "s/^${uname}:.+$/${new_pw}/" /etc/shadow

        log INFO "Updated shadow file for ${uname} with central password"
      fi
    fi
  fi

}

# Setup or replace a user
# setup_user <username> (noreplace) <uid>
# If the user has a uid, the passwords file will be named "<username>,<uid>"
# otherwise it will just be "<username>"
function setup_user() {
  local uname=$1
  local noreplace=$2
  local uid=$3

  local gdir=${USER_CONFIGS_DIR}/groups
  local pwdir=${USER_CONFIGS_DIR}/passwords
  local disable=${USER_CONFIGS_DIR}/disable

  unset IFS

  # Set a variable indicating if the user exists
  local user_exists=$(getent passwd ${uname})

  # If a uid was provided, setup the password filename and
  # additional arguments for user creation
  if [ -z "$uid" ]; then
    local adduseruid=""
    local pwf=${uname}
  else
    local adduseruid="--uid=${uid}"
    local pwf=${uname},${uid}
  fi

  if [ -z "${user_exists}" ]; then
    local group_exists=$(getent group ${uname})
    if [ -z "${group_exists}" ]; then
      local group_arg=""
    else
      local group_arg="-g ${uname}"
    fi
    adduser ${uname} ${adduseruid} ${group_arg}
    log INFO "setup_user: Added user ${uname} ${adduseruid} ${group_arg}"
  fi

  if [ -z "${user_exists}" ] || [ "${noreplace}" != "noreplace" ]; then
    log INFO "User does not exist (user_exists=${user_exists}) or we are told to replace replace existing one (noreplace=${noreplace}): ${uname} ${uid}"

    # We no longer get passwords from the individual box files, instead using the central password files for the actual password
    # The existence of the box user_config user just indicates the existence of the user on this box.

    local currid=$(getent passwd ${uname} | awk -F: '{print $3}')

    # If the user existed, has a uid specified and we have asked to replace, set the uid if it is different
    if [ "${user_exists}" ] && [ "${noreplace}" != "noreplace" ] && [ "${uid}" ] && [ "${currid}" != "${uid}" ]; then
      usermod -u ${uid} ${uname}
    fi

  fi

  # Set the number of days warning (defaults 14 but override if required)
  PW_EXP_WARN_DAYS=${PW_EXP_WARN_DAYS:=14}
  chage -W ${PW_EXP_WARN_DAYS} ${uname} 2>&1

  # If the user is not locked or this is not the user master server
  # update the actual password (shadow file entry)
  # with the password from the central config file
  echo "Trying update" > /home/${uname}/common.log

  if [ "$(is_user_locked "${uname}")" != 'locked' ] || [ "$(is_user_master)" != master ]; then
    echo "Updating" >> /home/${uname}/common.log
    update_shadow_with_central_password ${uname}
  fi

  # If the user has a groups file, add each group in it
  # Note: we don't remove groups that are not in the file, since
  # other setups add users to groups manually during setup
  if [ -f "${gdir}/${uname}" ]; then
    for g in $(cat "${gdir}/${uname}"); do
      if ! id -nGz "${uname}" | grep -qzxF "$g"; then
        usermod -aG ${g} ${uname} 2>&1
        log INFO "Added group ${g} to user ${uname}"
      fi
    done
  fi

  # If the user has not been marked as disabled in the disable or disable-all folders
  if [ ! -f ${disable}*/${uname} ]; then
    if [ -z "${user_exists}" ]; then
      # The user didn't exist. Follow up with post-create actions
      created_user_actions ${uname}
    else
      # The user existed (but may have previously been locked)
      # Re-enable their account, just in case
      usermod -U ${uname} 2>&1
      usermod -s /bin/bash ${uname} 2>&1
    fi
  fi
}

function is_user_master() {
  if [ "${MASTER_USERS_HOSTNAME}" == $(hostname) ]; then
    echo master
  fi
}

# Compare configured passwords with current entries in the shadow file
# For those where the current password is newer, send it to s3
function send_users_to_s3() {

  if [ "$(is_user_master)" != master ]; then
    return
  fi

  log_function $@

  mkdir -p ${CENTRAL_PW_DIR}
  chmod 770 ${CENTRAL_PW_DIR}
  log INFO "Got files: $(ls ${CENTRAL_PW_DIR} | wc -l)"

  for uname in $(list_setup_users); do
    cd ${CENTRAL_PW_DIR}
    unset ufile
    unset configpw
    unset configpwdate
    unset currpw
    unset currpwdate
    unset diffpw

    # Get the user's current password entry into variable currpw
    # Put the last password change date from the file into variable currpwdate
    # If the currpwdate is blank (the user is not a login user and has never
    # updated the password for example) then set the currpwdate to 0
    local currpw=$(getent shadow ${uname})
    if [ "${currpw}" ]; then
      local currpwdate=$(echo "${currpw}" | awk -F: '{print $3}')
    fi
    local currpwdate="${currpwdate:=0}"

    # Check for a /etc/central_passwords file for the user
    # If one exists, put the password entry from that file into variable configpw
    # and the last password change date into the variable configpwdate.
    local ufile="${CENTRAL_PW_DIR}/${uname}"
    if [ -f "${uname}" ]; then
      local configpw=$(cat "${ufile}")
    fi

    if [ "${configpw}" ]; then
      local configpwdate=$(echo "${configpw}" | awk -F: '{print $3}')
    fi
    local configpwdate="${configpwdate:=0}"

    # If the current password date is more recent (or the same) as the config password date
    # and the password entries do not match, then update the central file
    # Otherwise, if the current password is set, but there was no config, create an entry.
    if [ "${currpw}" ] && [ "${configpw}" ] && [ "${currpwdate}" -ge "${configpwdate}" ] && [ "${currpw}" != "${configpw}" ]; then
      # A password has been updated, copy it to the configuration file
      echo "${currpw}" > "${ufile}"
      log INFO "send_users_to_s3: has been updated - ${uname}"
    elif [ "${currpw}" ] && [ ! "${configpw}" ]; then
      # A password does not exist centrally yet, copy it to the configuration file
      echo "${currpw}" > "${ufile}"
      log INFO "send_users_to_s3: has been created - ${uname}"
    fi

  done

  # Sync all updated password configuration up to a common S3
  # bucket/user_configs/passwords folder
  cd /etc
  aws s3 cp --recursive central_passwords/ s3://${SERVICE_ASSETS_BUCKET}/user_configs/passwords/ --exclude=".*"
  cd -

  log INFO "send_users_to_s3: done"
}

# Get the central password file path for a username (first argument)
# ensuring the result is renamed to the simple username, not
# <username,id> as some might have
function get_central_password_file() {
  log_function $@

  local uname=$1

  mkdir -p ${CENTRAL_PW_DIR}
  chmod 770 ${CENTRAL_PW_DIR}

  if [ "${uname}" ]; then

    # If we are not retrieving all central password files once at the beginning of the process
    # then explicitly request this file
    if [ "${SYNC_CENTRAL_PASSWORD_FILES_ONCE}" != 'true' ]; then
      rm -f ${CENTRAL_PW_DIR}/${uname}
      rm -f ${CENTRAL_PW_DIR}/${uname},*
      # Retrieve the file and return the new path/filename
      aws s3 cp --only-show-errors s3://${SERVICE_ASSETS_BUCKET}/user_configs/passwords/${uname} ${CENTRAL_PW_DIR}/${uname}
    fi

    # Whether the file has been retrieved right now, or previously as a bulk action,
    # check its existence, and if it is present return the file path.
    if [ -f "${CENTRAL_PW_DIR}/${uname}" ]; then
      echo "${CENTRAL_PW_DIR}/${uname}"
    fi
  fi
}

function get_all_central_password_files() {
  log_function $@

  mkdir -p ${CENTRAL_PW_DIR}
  chmod 770 ${CENTRAL_PW_DIR}

  aws s3 sync --exact-timestamps s3://${SERVICE_ASSETS_BUCKET}/user_configs/passwords/ ${CENTRAL_PW_DIR}/
  local numres=$(ls ${CENTRAL_PW_DIR} | wc -l)
  if [ $numres == 0 ]; then
    SYNC_CENTRAL_PASSWORD_FILES_ONCE=false
  fi
  log INFO "Got central password files: $numres"
}

# For each item in passwords user_configs/directory, setup
# (or refresh the details for) a user
function setup_users() {
  log_function $@

  local pwdir=${USER_CONFIGS_DIR}/passwords
  local disable=${USER_CONFIGS_DIR}/disable

  local noreplace=$1

  groupadd -f ${ADMIN_GROUP}

  if [ "${noreplace}" != "noreplace" ]; then
    local noreplace='replace'
  fi

  setup_grouplist
  chown :${ADMIN_GROUP} ${USER_CONFIGS_DIR}

  if [ "${SYNC_CENTRAL_PASSWORD_FILES_ONCE}" == 'true' ]; then
    get_all_central_password_files
  fi

  unset IFS
  for f in $(ls ${pwdir}); do
    IFS=','
    read -a strarr <<< "$f"
    unset IFS
    local un="${strarr[0]}"
    local uid="${strarr[1]}"
    setup_user "${un}" "${noreplace}" ${uid}

  done
  unset IFS

  # If a user is listed in a disable directory, remove their access
  if [ -d ${disable} ] || [ -d ${disable}-all ]; then

    # Make the disable directory usable by admin scripts
    chown :${ADMIN_GROUP} "${disable}"*
    chmod 770 "${disable}"*

    for f in $(ls ${disable}*); do
      if [ "$(is_user_locked "${f}")" != 'locked' ] && [ "$(id ${f} 2> /dev/null)" ]; then
        usermod -L ${f} 2>&1
        chage -E0 ${f} 2>&1
        usermod -s /sbin/nologin ${f} 2>&1
        killall -u ${f}
        log INFO "Disabled user account ${f} and killed all related processes"
      fi
    done
  fi

  send_users_to_s3

  run_admin_actions

}


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


##### SSH

function setup_ssh_keys() {
  log_function $@

  if do_once; then
    sed -i -E 's/AuthorizedKeysFile .+/AuthorizedKeysFile \/etc\/user_configs\/ssh\/authorized_keys\/%u/g' /etc/ssh/sshd_config
    service sshd restart
    add_status
  fi

  for f in $(ls ${SSH_AUTH_KEYS}); do
    chown $f:root ${SSH_AUTH_KEYS}/${f}
    chmod 400 ${SSH_AUTH_KEYS}/${f}
  done
}

function setup_ssh_allow_passwords() {
  log_function $@

  sed -i -E 's/PasswordAuthentication .+/PasswordAuthentication yes/g' /etc/ssh/sshd_config
  service sshd restart
}

####### GNOME 
# Args:
#   Function name
#   Script
function setup_autostart_exec() {

  local fn=$1
  local script=$2

  echo "${script}" > /usr/local/bin/${fn}
  chmod 775 /usr/local/bin/${fn}

  cat > /etc/xdg/autostart/${fn}.desktop << EOF
[Desktop Entry]
Encoding=UTF-8
Exec=/usr/local/bin/${fn}
Name=run-${fn}
Comment=Autostart Run ${fn}
Terminal=false
OnlyShowIn=GNOME
Type=Application
StartupNotify=false
X-GNOME-Autostart-enabled=true
NoDisplay=true
EOF

}


#######  2FA


function disable_root_login_ssh() {
  log_function $@
  sed -i -E "s/.*PermitRootLogin .*/PermitRootLogin no/g" /etc/ssh/sshd_config
  service sshd restart
}

function pull_two_factor_auth_setups() {
  log_function $@
  do_once || return

  for f in $(list_setup_users); do
    local gafile=${USER_BASE_DIRS}/${f}/.google_authenticator
    if [ -f ${gafile} ]; then
      local gatarget=/home/${f}/.google_authenticator
      cp -f ${gafile} ${gatarget}
      chown ${f}:${f} ${gatarget}
      chmod 600 ${gatarget}
      log INFO "Copied back .google_authenticator file for ${f}"
    fi
  done

  add_status
}

# Must be run after GNOME is installed if you are using VNC/RDP
function setup_two_factor_auth() {
  log_function $@
  do_once || return

  yum install -y google-authenticator

  pull_two_factor_auth_setups

  # Make users setup 2FA
  cat > ${SETUP_2FA} << EOF
#!/bin/bash
rm -f \${HOME}/.google_authenticator 
rm -f \${HOME}/.google_authenticator-prep
google-authenticator -t -d -Q UTF8 -r 6 -R 30 -w 3 -f
mv \${HOME}/.google_authenticator \${HOME}/.google_authenticator-prep

cat << DONE1
=======================================================================
* IMPORTANT - do not close this window                                *
*                                                                     *
* You do not have two factor authentication set up for your account   *
* To ensure your account is compliant, scan the QR code with your     *
* authenticator app now. Any of the following apps are known to work  *
* Duo Mobile, Google Authenticator, Microsoft Authenticator and Authy *
=======================================================================
=======================================================================
* When you have set up your authenticator app:                        *
* Click on this window, then press Enter.                             *
=======================================================================
DONE1
read
rm -f \${HOME}/.google_authenticator 
mv \${HOME}/.google_authenticator-prep \${HOME}/.google_authenticator
cp -f \${HOME}/.google_authenticator ${USER_BASE_DIRS}/\${USER}/
if [ -f \${HOME}/.google_authenticator-prep ] || [ ! -f \${HOME}/.google_authenticator ] ; then
  clear
  echo "Something went wrong setting up the authenticator."
  echo "Please try again"
  echo "Press enter to continue"
  read $press_enter
  clear
  ${SETUP_2FA}
fi
EOF

  cat > "${SETUP_2FA}-onstart" << EOF
if [ ! -f \${HOME}/.google_authenticator ]; then
  gnome-terminal --geometry=80x50 -- setup-2fa
fi 
EOF

  cat > /etc/xdg/autostart/setup_2fa.desktop << EOF
[Desktop Entry]
Encoding=UTF-8
Exec=${SETUP_2FA}-onstart
Name=authenticate-2fa
Comment=Setup user 2FA
Terminal=false
OnlyShowIn=GNOME
Type=Application
StartupNotify=false
X-GNOME-Autostart-enabled=true
EOF

  chmod 775 ${SETUP_2FA}
  chmod 775 ${SETUP_2FA}-onstart

  # Tell PAM to optionally use 2FA
  echo "auth required pam_google_authenticator.so nullok" >> /etc/pam.d/sshd
  #sed -i -E "s/auth.+substack.+password-auth/# auth substack password-auth/g" /etc/pam.d/sshd

  # Setup SSH

  sed -i -E "s/^ChallengeResponseAuthentication .*/ChallengeResponseAuthentication yes/g" /etc/ssh/sshd_config
  echo "ClientAliveInterval 120" >> /etc/ssh/sshd_config
  echo "ClientAliveCountMax 2" >> /etc/ssh/sshd_config
  echo "AuthenticationMethods publickey,password publickey,keyboard-interactive" >> /etc/ssh/sshd_config
  systemctl restart sshd.service

  # Setup GNOME login

  if [ -f /etc/pam.d/gdm-password ]; then
    echo "auth required pam_google_authenticator.so nullok" >> /etc/pam.d/gdm-password
  fi

  # Direct login
  echo "auth required pam_google_authenticator.so nullok" >> /etc/pam.d/login

  add_status
}

function reset_google_auths() {

  local reset2fa=${USER_CONFIGS_DIR}/reset2fa
  mkdir -p "${reset2fa}"
  chown :${ADMIN_GROUP} "${reset2fa}"
  chmod 770 "${reset2fa}"

  log INFO "Resetting google authenticator for users listed in ${reset2fa} :" $(ls "${reset2fa}")

  for f in $(ls "${reset2fa}"); do
    rm -f /home/${f}/.google_authenticator
    rm -f ${USER_BASE_DIRS}/${f}/.google_authenticator
    rm -f ${reset2fa}/${f}
    log INFO "Reset google authenticator for ${f}"

  done

}
