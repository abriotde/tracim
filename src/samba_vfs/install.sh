#!/bin/bash

PROJECT_NAME=samba_vfs_service
SUPERVISOR_CONF="/tracim/tools_docker/Debian_Uwsgi/supervisord_tracim.conf"

function configure_supervisor {
	grep "$PROJECT_NAME" $SUPERVISOR_CONF >/dev/null
	status=$?
	if [ "$status" -eq 0 ]; then
		echo "Module $PROJECT_NAME already exists in $SUPERVISOR_CONF."
	else
		echo "Adding samba vfs service to supervisord_tracim.conf... "
		cat >>$SUPERVISOR_CONF <<EOF

# samba vfs service
[program:samba_vfs_service]
user=www-data
directory=/tracim/backend/
command=python3 /tracim/backend/daemons/samba_vfs_service.py
stdout_logfile =/var/tracim/logs/samba_vfs_service.log
redirect_stderr=true
autostart=false
autorestart=false
environment=TRACIM_CONF_PATH=/etc/tracim/development.ini
EOF
	fi
}

function reload_supervisor {
	supervisorctl reload
	supervisorctl status $PROJECT_NAME >/dev/null
	status=$?
	if [ "$status" -eq 0 ]; then
		echo "Module $PROJECT_NAME already running, stopping it."
		supervisorctl stop $PROJECT_NAME
	fi
	echo "Starting $PROJECT_NAME."
	supervisorctl start $PROJECT_NAME
}

configure_supervisor
# reload_supervisor