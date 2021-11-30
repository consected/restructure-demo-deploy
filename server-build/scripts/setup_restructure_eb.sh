RESTR_FS_ROOT=${RESTR_FS_ROOT:=/efs1}
RESTR_FS_DIR=${RESTR_FS_DIR:=${BOX_NAME}-main}
RESTR_MOUNT_ROOT=${RESTR_MOUNT_ROOT:=/mnt/fphsfs}
RESTR_WEBAPP_USER=${RESTR_WEBAPP_USER:=webapp}
REMOUNT_EFS_SCRIPT=/root/setup/remount_efs.sh
BIND_GROUPS='600 601 602'
BIND_USER_ID=600
# LO_MINOR_VERSION=6.1
# LO_VERSION=${LO_MINOR_VERSION}.5
LO_MINOR_VERSION=6.4
LO_VERSION=${LO_MINOR_VERSION}.4
LO_PATCH_VERSION=${LO_VERSION}.2
LO_TAR=LibreOffice_${LO_VERSION}_Linux_x86-64_rpm.tar.gz

function setup_restructure_eb() {
  do_once || return
  log_function $@

  install_restructure_basics
  install_memcached
  configure_efs
  install_libreoffice
  install_dicom_toolkit
  install_netpbm
  add_instance_private_ip
  enable_webapp_restart

  add_status
}

function install_restructure_basics() {
  do_once || return
  log_function $@

  amazon-linux-extras install -y epel
  yum install -y bindfs autoconf fuse fuse-libs fuse-devel libarchive libarchive-devel amazon-efs-utils

  # Setup a cleanup cronjob that calls app-scripts/temfile-cleanup.sh
  init_templates general
  use_template general /etc/cron.d/app-cleanup

  add_status
}

function install_memcached() {
  do_once || return
  log_function $@

  amazon-linux-extras install -y memcached1.5
  yum install -y memcached
  systemctl restart memcached

  add_status
}

function configure_efs() {
  log_function $@

  local FS_ROOT=${RESTR_FS_ROOT}
  local FS_DIR=${RESTR_FS_DIR}
  local MOUNT_ROOT=${RESTR_MOUNT_ROOT}
  local WEBAPP_USER=${RESTR_WEBAPP_USER}
  local EFS_ID=${RESTR_EFS_ID}

  if [ ! "${FS_ROOT}" ] || [ ! "${FS_DIR}" ] || [ ! "${MOUNT_ROOT}" ] || [ ! "${WEBAPP_USER}" ] || [ ! "${EFS_ID}" ]; then
    log ERROR "Variables not set: FS_ROOT=${RESTR_FS_ROOT} FS_DIR=${RESTR_FS_DIR} MOUNT_ROOT=${RESTR_MOUNT_ROOT} WEBAPP_USER=${RESTR_WEBAPP_USER} EFS_ID=${RESTR_EFS_ID}"
    return 9
  fi

  # Create a script to run for remounting efs on future reboots
  if [ ! -f ${REMOUNT_EFS_SCRIPT} ]; then
    cat > ${REMOUNT_EFS_SCRIPT} << EOF
#!/bin/bash
cd /root/setup
if [ -f common_functions.sh ]; then
  . common_functions.sh
  get_source setup_restructure_eb.sh
  RESTR_FS_ROOT=${RESTR_FS_ROOT}
  RESTR_FS_DIR=${RESTR_FS_DIR}
  RESTR_MOUNT_ROOT=${RESTR_MOUNT_ROOT}
  RESTR_WEBAPP_USER=${RESTR_WEBAPP_USER}
  RESTR_EFS_ID=${RESTR_EFS_ID}
  configure_efs
fi
EOF
  fi

  chmod 700 ${REMOUNT_EFS_SCRIPT}

  init_templates rebooter
  use_template rebooter /usr/lib/systemd/system/mount-on-boot.service
  systemctl enable mount-on-boot

  # Now run the actual setup
  log INFO "Using variables: FS_ROOT=${RESTR_FS_ROOT} FS_DIR=${RESTR_FS_DIR} MOUNT_ROOT=${RESTR_MOUNT_ROOT} WEBAPP_USER=${RESTR_WEBAPP_USER} EFS_ID=${RESTR_EFS_ID}"

  mkdir -p $FS_ROOT
  getent group 599 || groupadd --gid 599 nfs_store_all_access
  getent group 600 || groupadd --gid 600 nfs_store_group_0
  getent group 601 || groupadd --gid 601 nfs_store_group_1
  getent passwd ${BIND_USER_ID} || useradd --user-group --uid ${BIND_USER_ID} nfsuser
  usermod -a --groups=599,600,601 $WEBAPP_USER
  usermod -a --groups=599,600,601 root
  mkdir -p $FS_ROOT
  mountpoint -q $FS_ROOT || mount -t efs -o tls ${EFS_ID}:/ $FS_ROOT
  log INFO "mountpoint ${FS_ROOT}: $(mountpoint ${FS_ROOT})"
  if [ "$(mountpoint -q ${FS_ROOT})" ]; then
    log ERROR "Failed to mount EFS ${EFS_ID} at ${FS_ROOT}"
    return 7
  fi

  cd $FS_ROOT
  mkdir -p $FS_DIR

  for m in ${BIND_GROUPS}; do
    mkdir -p $MOUNT_ROOT/gid${m}
    mountpoint -q $MOUNT_ROOT/gid${m} || bindfs --map=@${m}/@599 --create-for-group=${m} --create-for-user=${BIND_USER_ID} --chown-ignore --chmod-ignore --create-with-perms='u=rwD:g=rwD:o=' $FS_ROOT/$FS_DIR $MOUNT_ROOT/gid${m}
    if [ "$(mountpoint $MOUNT_ROOT/gid${m} | grep 'is not a mountpoint')" ]; then
      log ERROR "Failed to bind mount EFS ${EFS_ID} for $FS_ROOT/$FS_DIR $MOUNT_ROOT/gid${m}"
      return 8
    else
      log INFO "Bind mount ${m} successful"
    fi
  done

  add_status
}

function install_libreoffice() {
  log_function $@

  if [ -f '/usr/bin/libreoffice' ]; then
    log INFO "Libreoffice already installed"
  else
    yum install -y cups dbus-libs dbus-glib
    cd /tmp
    rm -f /usr/bin/libreoffice
    aws s3 cp s3://${INSTALL_ASSETS_BUCKET}/${LO_TAR} . --region=${AWS_REGION}
    tar -xzf ${LO_TAR}
    rm -f ${LO_TAR}
    cd LibreOffice_${LO_PATCH_VERSION}_Linux_x86-64_rpm/RPMS/
    yum localinstall -y *.rpm
    ln -s /usr/bin/libreoffice${LO_MINOR_VERSION} /usr/bin/libreoffice
    # Give webapp a home directory so libreoffice can store its config
    # No need for shell access though
    # chsh -s /bin/bash webapp
    mkdir /home/webapp
    chown webapp:webapp /home/webapp
    chmod 700 /home/webapp/
    echo "012,123" > a.csv
    sudo -u webapp libreoffice --headless --convert-to pdf a.csv
    cd /tmp
    rm -rf /tmp/LibreOffice_${LO_PATCH_VERSION}_Linux_x86-64_rpm

    libreoffice --headless --version
    if [ $? != 0 ]; then
      log ERROR "Failed to install libreoffice"
    else
      add_status
    fi
  fi

}

function install_dicom_toolkit() {
  log_function $@

  if [ -f '/usr/bin/dcmj2pnm' ]; then
    log INFO "dcmj2pnm already installed"
  else
    cd /tmp
    mkdir dcmtk
    cd dcmtk/
    aws s3 cp s3://${INSTALL_ASSETS_BUCKET}/dcmtk-3.6.4-install.tar.gz .
    tar -xzf dcmtk-3.6.4-install.tar.gz
    rm -f dcmtk-3.6.4-install.tar.gz
    cd dcmtk-3.6.4-install
    cp -R usr/local/* /usr/
    ln -s /usr/share/dcmtk /usr/local/share/dcmtk
    sudo -u webapp dcmj2pnm --version
    cd /tmp
    rm -rf /tmp/dcmtk
  fi

  add_status
}

function install_netpbm() {
  log_function $@

  if [ -f '/usr/bin/jpegtopnm' ]; then
    log INFO "netpbm already installed"
  else
    yum install -y netpbm netpbm-progs
  fi

  add_status
}

function add_instance_private_ip() {
  log_function $@

  if [ -z "${INSTANCE_ADD_PRIVATEIP}" ]; then
    log INFO "No INSTANCE_ADD_PRIVATEIP requested"
  else

    unset AWS_ACCESS_KEY_ID
    unset AWS_SECRET_ACCESS_KEY
    unset AWS_SESSION_TOKEN

    local INSTANCE_ID=$(echo $(ec2-metadata -i) | sed -n 's/instance-id: //p')
    local TMPIF=/tmp/describe-network-interfaces-deploy.json
    aws ec2 describe-network-interfaces --filters "Name=attachment.instance-id,Values=${INSTANCE_ID}" --region ${AWS_REGION} > ${TMPIF}

    local PIPSET=$(cat ${TMPIF} | grep "\"PrivateIpAddress\": \"${INSTANCE_ADD_PRIVATEIP}\"")
    if [ -z "${PIPSET}" ]; then
      local NETWORKIF=$(cat ${TMPIF} | grep "NetworkInterfaceId" | sed -n 's/.*"\(eni.\+\)",/\1/p')
      if [ "${NETWORKIF}" ]; then
        aws ec2 assign-private-ip-addresses --region=${AWS_REGION} --network-interface-id ${NETWORKIF} --private-ip-addresses ${INSTANCE_ADD_PRIVATEIP}
        sleep 5
        systemctl restart network
      fi
    fi

  fi
  add_status
}

# Allow user to restart jobs
function enable_webapp_restart() {
  log_function $@

  cat > /etc/sudoers.d/${RESTR_WEBAPP_USER} << SUDO
${RESTR_WEBAPP_USER} ALL= NOPASSWD: /bin/systemctl restart web.service
${RESTR_WEBAPP_USER} ALL= NOPASSWD: /bin/systemctl restart delayed_job.service
${RESTR_WEBAPP_USER} ALL= NOPASSWD: /bin/systemctl restart memcached.service
SUDO

  add_status
}
