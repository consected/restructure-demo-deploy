#!/bin/bash
CRON_DIR=/etc/cron.d
CERTBOT_FLAG=/root/setup/status_certbot_running-${BOX_NAME}
DEFAULT_IP=$(ip route get 1.1.1.1 | grep -oP 'src \K\S+')

function setup_certbot_docker() {
  do_once || return
  log_function $@

  local docker_was_inactive=$(systemctl is-active docker | grep "inactive")
  yum install -y docker
  systemctl start docker
  systemctl enable docker
  docker pull certbot/dns-route53

  if [ ! -z "${docker_was_inactive}" ]; then
    # Docker was previously inactive. Stop it again
    systemctl stop docker
  fi

  certbot_docker_refresher

  add_status

}

function certbot_docker_refresher() {
  log_function $@
  init_templates certbot_docker
  box_name=${BOX_NAME} SERVICE_ASSETS_BUCKET=${SERVICE_ASSETS_BUCKET} INTERNAL_HOSTNAME=${INTERNAL_HOSTNAME} EXTERNAL_HOSTNAME=${EXTERNAL_HOSTNAME} use_template certbot_docker ${CRON_DIR}/refreshcerts
}

# Check our standard server certificate
function check_certificate_valid() {
  if openssl x509 -checkend 604800 -noout -in /etc/pki/tls/certs/server.crt; then
    local res=valid
  fi
  echo ${res}
}

# Use environment variable FORCE_REISSUE=true to force the reissue even if certs appear to have a valid date
function certbot_issue_certificate() {
  log_function $@

  local INT_DOMAIN=$1
  local EXT_DOMAIN=$2
  local extra_args=$3

  if [ ! "${INT_DOMAIN}" ] || [ ! "${BOX_NAME}" ]; then
    log ERROR "Environment not setup correctly: ${INT_DOMAIN} & ${BOX_NAME}"
    exit 10
  fi

  local docker_was_inactive=$(systemctl is-active docker | grep "inactive")

  if [ -z ${EXT_DOMAIN} ]; then
    local ext_domain_flag=""
  else
    local ext_domain_flag="--domains ${EXT_DOMAIN}"
  fi

  lock_certbot

  get_certs_from_server_store

  local old_certs=$(find /etc/pki/tls/certs/ -name 'server.*' -mtime +35)

  if [ ! -e /etc/pki/tls/certs/server.key ] || [ ! -z "$old_certs" ] || [ "${FORCE_REISSUE}" == 'true' ] || [ "$(check_certificate_valid)" != 'valid' ]; then

    log INFO "Reissue certificates"
    log INFO "key file does not exist? $([ ! -e /etc/pki/tls/certs/server.key ] && echo 'does not exist' || echo 'exists')"
    log INFO "Certificate expiration: $(openssl x509 -enddate -noout -in /etc/pki/tls/certs/server.crt)"
    log INFO "old certs: ${old_certs}"
    log INFO "Checking for --domains ${INT_DOMAIN} ${ext_domain_flag}"

    # Ensure docker is in a good state, and iptables are set
    systemctl restart docker

    rm -rf /etc/letsencrypt/live/*
    rm -rf /etc/letsencrypt/archive/*

    # Another check on the lock
    lock_certbot

    docker run --rm --name dns-route53 \
      -v "/var/log/letsencrypt:/var/log/letsencrypt" \
      -v "/etc/letsencrypt:/etc/letsencrypt" \
      -v "/var/lib/letsencrypt:/var/lib/letsencrypt" --privileged ${extra_args} \
      certbot/dns-route53 certonly \
      --non-interactive \
      --dns-route53 \
      --email phil.ayres@consected.com \
      --domains ${INT_DOMAIN} ${ext_domain_flag} \
      --dns-route53-propagation-seconds 20 \
      --agree-tos \
      --keep-until-expiring \
      --force-renewal

    if [ -f /etc/letsencrypt/live/${INT_DOMAIN}*/privkey.pem ]; then
      rm -f /etc/pki/tls/certs/server.key
      rm -f /etc/pki/tls/certs/server.crt
      ln -s /etc/letsencrypt/live/${INT_DOMAIN}*/privkey.pem /etc/pki/tls/certs/server.key
      ln -s /etc/letsencrypt/live/${INT_DOMAIN}*/fullchain.pem /etc/pki/tls/certs/server.crt
      save_certs_to_server_store
      certbot_issued_reboot_services

      if [ "$(check_certificate_valid)" == 'valid' ]; then
        log INFO "Certificate not expired: $(openssl x509 -enddate -noout -in /etc/pki/tls/certs/server.crt)"
      else
        log ERROR "Certificate will expire within 7 days, or has already expired: $(openssl x509 -enddate -noout -in /etc/pki/tls/certs/server.crt)"
      fi
    else
      log ERROR "New certificates not found"
    fi

    if [ ! -z "${docker_was_inactive}" ]; then
      # Docker was previously inactive. Stop it again
      systemctl stop docker
    fi

  else
    log INFO "Not reissuing certificates yet"
  fi

  echo '' > ${CERTBOT_FLAG}
  save_to_box_store ${CERTBOT_FLAG}
}

function lock_certbot() {
  log_function $@

  get_from_box_store ${CERTBOT_FLAG}

  if [ -f ${CERTBOT_FLAG} ]; then
    # Check certbot isn't running on another server
    local certbot_running_on=$(cat ${CERTBOT_FLAG})
    while [ "${certbot_running_on}" ] && [ "${certbot_running_on}" != ${DEFAULT_IP} ]; do
      log INFO "Waiting for another certbot to finish: ${certbot_running_on}"
      get_from_box_store ${CERTBOT_FLAG}
      certbot_running_on=$(cat ${CERTBOT_FLAG})
      sleep 30
    done
  fi

  echo ${DEFAULT_IP} > ${CERTBOT_FLAG}
  save_to_box_store ${CERTBOT_FLAG} any-age

}

function certbot_issued_reboot_services() {
  log_function $@
  local services='httpd passenger nginx web vpnserver'
  for svc in ${services}; do
    if [ "$(service_enabled ${svc})" ] && [ -z "$(service_not_running ${svc})" ]; then
      log INFO "Restarting service ${svc} after certbot issued certificate"
      systemctl restart ${svc}
    fi
  done

  if [ -f /usr/local/bin/certbot_callback_after_issue.sh ]; then
    log INFO "Calling certbot_callback_after_issue.sh"
    /usr/local/bin/certbot_callback_after_issue.sh
  fi

  add_status
}

function save_certs_to_server_store() {
  log_function $@

  save_to_box_store /etc/pki/tls/certs/server.key
  save_to_box_store /etc/pki/tls/certs/server.crt

}

function get_certs_from_server_store() {

  log_function $@
  get_from_box_store /etc/pki/tls/certs/server.key
  get_from_box_store /etc/pki/tls/certs/server.crt

}
