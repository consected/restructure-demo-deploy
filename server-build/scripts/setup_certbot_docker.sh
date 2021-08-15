#!/bin/bash
CRON_DIR=/etc/cron.d

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

# Use environment variable FORCE_REISSUE=true to force the reissue even if certs appear to have a valid date
function certbot_issue_certificate() {
  log_function $@

  local INT_DOMAIN=$1
  local EXT_DOMAIN=$2
  local extra_args=$3

  local docker_was_inactive=$(systemctl is-active docker | grep "inactive")

  if [ -z ${EXT_DOMAIN} ]; then
    local ext_domain_flag=""
  else
    local ext_domain_flag="--domains ${EXT_DOMAIN}"
  fi

  get_certs_from_server_store

  local old_certs=$(find /etc/pki/tls/certs/ -name 'server.*' -mtime +35)

  if [ ! -e /etc/pki/tls/certs/server.key ] || [ ! -z "$old_certs" ] || [ "$FORCE_REISSUE" == 'true' ]; then

    log INFO "Reissue certificates"

    # Ensure docker is in a good state, and iptables are set
    systemctl restart docker

    rm -rf /etc/letsencrypt/live/*
    rm -rf /etc/letsencrypt/archive/*

    docker run --rm --name dns-route53 \
      -v "/var/log/letsencrypt:/var/log/letsencrypt" \
      -v "/etc/letsencrypt:/etc/letsencrypt" \
      -v "/var/lib/letsencrypt:/var/lib/letsencrypt" --privileged ${extra_args} \
      certbot/dns-route53 certonly \
      --non-interactive \
      --dns-route53 \
      --email phil.ayres@consected.com \
      --domains ${INT_DOMAIN} ${ext_domain_flag} \
      --dns-route53-propagation-seconds	20 \
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
