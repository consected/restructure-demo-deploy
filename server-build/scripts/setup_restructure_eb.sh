RESTR_FS_ROOT=${RESTR_FS_ROOT:=/efs1}
RESTR_FS_DIR=${RESTR_FS_DIR:=appdev-main}
RESTR_MOUNT_ROOT=${RESTR_MOUNT_ROOT:=/mnt/fphsfs}
RESTR_WEBAPP_USER=${RESTR_WEBAPP_USER:=webapp}
REMOUNT_EFS_SCRIPT=/root/setup/remount_efs.sh

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

  mkdir -p $FS_ROOT
  getent group 599 || groupadd --gid 599 nfs_store_all_access
  getent group 600 || groupadd --gid 600 nfs_store_group_0
  getent group 601 || groupadd --gid 601 nfs_store_group_1
  getent passwd 600 || useradd --user-group --uid 600 nfsuser
  usermod -a --groups=599,600,601 $WEBAPP_USER
  usermod -a --groups=599,600,601 root
  mkdir -p $FS_ROOT
  mountpoint -q $FS_ROOT || mount -t efs -o tls ${EFS_ID}:/ $FS_ROOT
  mkdir -p $MOUNT_ROOT/gid600
  mkdir -p $MOUNT_ROOT/gid601
  mountpoint -q $MOUNT_ROOT/gid600 || bindfs --map=@600/@599 --create-for-group=600 --create-for-user=600 --chown-ignore --chmod-ignore --create-with-perms='u=rwD:g=rwD:o=' $FS_ROOT/$FS_DIR $MOUNT_ROOT/gid600
  mountpoint -q $MOUNT_ROOT/gid601 || bindfs --map=@601/@599 --create-for-group=601 --create-for-user=600 --chown-ignore --chmod-ignore --create-with-perms='u=rwD:g=rwD:o=' $FS_ROOT/$FS_DIR $MOUNT_ROOT/gid601

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

  add_status
}

function install_libreoffice() {
  log_function $@

  if [ -f '/usr/bin/libreoffice' ]; then
    log INFO "Libreoffice already installed"
  else
    yum install -y cups dbus-libs dbus-glib
    cd /tmp
    wget https://s3.amazonaws.com/${INSTALL_ASSETS_BUCKET}/LibreOffice_6.1.5_Linux_x86-64_rpm.tar.gz
    tar -xzf LibreOffice_6.1.5_Linux_x86-64_rpm.tar.gz
    rm LibreOffice_6.1.5_Linux_x86-64_rpm.tar.gz
    cd LibreOffice_6.1.5.2_Linux_x86-64_rpm/RPMS/
    yum localinstall -y *.rpm
    ln -s /usr/bin/libreoffice6.1 /usr/bin/libreoffice
    # Give webapp a home directory so libreoffice can store its config
    # No need for shell access though
    # chsh -s /bin/bash webapp
    mkdir /home/webapp
    chown webapp:webapp /home/webapp
    chmod 700 /home/webapp/
    echo "012,123" > a.csv
    sudo -u webapp libreoffice --headless --convert-to pdf a.csv
    cd /tmp
    rm -rf /tmp/LibreOffice_6.1.5.2_Linux_x86-64_rpm
  fi

  add_status
}

function install_dicom_toolkit() {
  log_function $@

  if [ -f '/usr/bin/dcmj2pnm' ]; then
    log INFO "dcmj2pnm already installed"
  else
    cd /tmp
    mkdir dcmtk
    cd dcmtk/
    wget https://s3.amazonaws.com/${INSTALL_ASSETS_BUCKET}/dcmtk-3.6.4-install.tar.gz
    tar -xzf dcmtk-3.6.4-install.tar.gz
    rm dcmtk-3.6.4-install.tar.gz
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
