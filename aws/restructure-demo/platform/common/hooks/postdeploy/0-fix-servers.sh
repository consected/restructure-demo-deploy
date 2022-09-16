#!/bin/bash
# There have been issues with ownership of nginx directories and missing log directory. Fix this

chown nginx /var/log/nginx /var/log/nginx/healthd /var/lib/nginx /var/lib/nginx/tmp
mkdir -p /var/log/app-log
chown webapp /var/log/app-log
[ ! -d /var/app/current/log ] && ln -s /var/log/app-log /var/app/current/log
mkdir -p /var/app/current/db/app_migrations
chown webapp:webapp /var/app/current/db/app_migrations
mkdir -p /var/app/current/tmp/pids
chown webapp:webapp /var/app/current/tmp/pids
echo "0-fix-servers.sh run successfully"
