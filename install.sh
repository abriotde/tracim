#!/bin/bash
#
# Deployment script for Database VFS module and Python service
#

# set -e

echo "===== Database VFS Module Deployment ====="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

BASE_NAME="tracim"
PROJECT_NAME="vfs_$BASE_NAME"
PROJECT_NAME_UPPER="VFS_TRACIM"

VFS_C_SOURCE="$PROJECT_NAME.c"
# Configuration variables
PWD=$(pwd)
SAMBA_SOURCE=$PWD/samba
SRC_DIR="$PWD/src"
PYTHON_SERVICE_DIR="/tracim/backend/daemons/"
SOCKET_PATH="/srv/tracim"
LOG_FILE="/var/log/$PROJECT_NAME.log"
SYSTEMD_SERVICE_FILE="/etc/systemd/system/$PROJECT_NAME.service"
OS_SAMBA_MODULES_DIR="/usr/lib/x86_64-linux-gnu/samba/vfs"
SMB_MODULES_DIR="$SAMBA_SOURCE/source3/modules"
TRACIM_DOCKER_CONTAINER="tracim-tracim-1"


# Create directories if they don't exist
touch "$LOG_FILE"
chmod 666 "$LOG_FILE"

function install_deps {
	# Install dependencies
	echo "Installing dependencies..."
	apt-get update > /dev/null 2>&1
	apt install -y build-essential libjson-c-dev \
		samba-dev libsmbclient-dev \
		python3-dev python3-pip  \
		liblmdb-dev lmdb-utils libgpgme11-dev libparse-yapp-perl \
		libjansson-dev libarchive-dev libutf8proc-dev > /dev/null 2>&1
	apt install -y \
		build-essential \
		git \
		gcc \
		libdbus \
		libacl1-dev \
		libattr1-dev \
		libblkid-dev \
		libgnutls28-dev \
		libreadline-dev \
		python3-dnspython \
		libbsd-dev \
		libpopt-dev \
		libldap2-dev \
		libtalloc-dev \
		libtdb-dev \
		libtevent-dev \
		libkrb5-dev \
		libldb-dev \
		libncurses5-dev \
		libpam0g-dev \
		libcups2-dev \
		libjson-c-dev \
		flex \
		bison \
		pkg-config \
		python3-setuptools \
		python3-markdown \
		xsltproc \
		docbook-xsl \
		libgpgme-dev \
		uuid-dev \
		libjansson-dev > /dev/null 2>&1
}

function load_samba_source {
	echo "Load Samba source directory"
	# wget https://download.samba.org/pub/samba/samba-latest.tar.gz
	# tar -xvf samba-latest.tar.gz
	# samba-4.22.2
	git submodule update --init --recursive > /dev/null 2>&1
	if [ ! -d "$SAMBA_SOURCE" ]; then
		echo "Error: Samba source directory not found at: $SAMBA_SOURCE"
		echo "Please update the SAMBA_SOURCE variable in this script."
		exit 1
	fi
	SMBD_VERSION=$(smbd --version | awk -F" |-" '{print $2}')
	cd $SAMBA_SOURCE
	git tag -l | grep "^samba-$SMBD_VERSION\$"
	if [ $? -eq 0 ]; then
		echo "Samba git checkout to matches your smbd server version ($SMBD_VERSION). git checkout --force tags/samba-$SMBD_VERSION"
		git checkout --force tags/samba-$SMBD_VERSION > /dev/null
	fi
	source $SAMBA_SOURCE/VERSION
	SAMBA_SOURCE_VERSION="$SAMBA_VERSION_MAJOR.$SAMBA_VERSION_MINOR.$SAMBA_VERSION_RELEASE"
	if [ "x$SAMBA_SOURCE_VERSION" != "x$SMBD_VERSION" ]; then
		echo "Error: Unable to match Samba source version with your smbd server ($SMBD_VERSION != $SAMBA_SOURCE_VERSION)."
		exit 1
	fi
}

function compile_vfs_module {
	echo "Add VFS module to Samba..."
	echo "EXEC: cp $SRC_DIR/$VFS_C_SOURCE $SMB_MODULES_DIR/"
	cp $SRC_DIR/$VFS_C_SOURCE $SMB_MODULES_DIR/

	# echo "EXEC: grep $PROJECT_NAME $SMB_MODULES_DIR/../wscript  /dev/null"
	grep "$PROJECT_NAME" $SMB_MODULES_DIR/../wscript >> /dev/null
	status=$?
	if [ "$status" -eq 0 ]; then
		echo "Module $PROJECT_NAME already exists in wscript."
	else
		echo -n "Adding module $PROJECT_NAME to wscript... "
		# echo "sed -i "/default_shared_modules.extend.*vfs_recycle/ s/$/ \'$PROJECT_NAME\',/" $SMB_MODULES_DIR/../wscript"
		sed -i "/default_shared_modules.extend.*vfs_recycle/ s/$/ \'$PROJECT_NAME\',/" $SMB_MODULES_DIR/../wscript
		grep "$PROJECT_NAME" $SMB_MODULES_DIR/../wscript >> /dev/null
		status=$?
		if [ "$status" -eq 0 ]; then
			echo " Ok."
		else
			echo " Error : Fail adding module $PROJECT_NAME to wscript."
			echo "Try adding it mannualy : Edit file '$SMB_MODULES_DIR/../wscript' and add to the list of modules in 'default_shared_modules.extend' the '$PROJECT_NAME'."
			exit 1
		fi
	fi

	grep "$PROJECT_NAME" $SMB_MODULES_DIR/wscript_build >> /dev/null
	status=$?
	if [ "$status" -eq 0 ]; then
		echo "Module $PROJECT_NAME already exists in wscript_build."
	else
		echo "Adding module $PROJECT_NAME to wscript_build... "
		cat >>$SMB_MODULES_DIR/wscript_build <<EOF

bld.SAMBA3_MODULE('$PROJECT_NAME',
                subsystem='vfs',
                source='$VFS_C_SOURCE',
                deps='POSIXACL_XATTR samba-util jansson',
                init_function='',
				internal_module=False,
                # internal_module=bld.SAMBA3_IS_STATIC_MODULE('$PROJECT_NAME'),
				enabled=True
                # enabled=bld.SAMBA3_IS_ENABLED_MODULE('$PROJECT_NAME')
			)
EOF
		grep "$PROJECT_NAME" $SMB_MODULES_DIR/wscript_build >> /dev/null
		status=$?
		if [ "$status" -eq 0 ]; then
			echo " Ok."
		else
			echo " Error : Fail adding module $PROJECT_NAME to wscript_build."
			echo "Try adding it mannualy : Edit file '$SMB_MODULES_DIR/wscript_build' and add the module definition for '$PROJECT_NAME'."
			exit 1
		fi
	fi

	cd $SAMBA_SOURCE
	if [ ! -f Makefile ]; then
		echo "Compiling VFS module..."
		# ./configure.developer --enable-debug # --without-ldb-lmdb
		# --enable-rust --with-himmelblau
		# ./configure --with-samba-source=/usr/include/samba-4.0
		./configure # --enable-tracim
	fi
	make # $PROJECT_NAME.so
	if [ $? -ne 0 ]; then
		echo "Failed to compile the VFS module"
		exit 1
	fi
}


# ./bin/default/source3/modules/libvfs_module_db_tracim.so
# ./bin/modules/vfs/db_tracim.so
SO_LIBRARY="libvfs_module_$BASE_NAME.so"
SO_LIBRARY2="$BASE_NAME.so"

function install_vfs_module {
	echo "Installing VFS module..."
	mkdir -p $SOCKET_PATH
	chmod 777 $SOCKET_PATH
	src=$SAMBA_SOURCE/bin/modules/vfs/$SO_LIBRARY2
	if [ -L $src ]; then
		src=$(readlink -ne $SAMBA_SOURCE/bin/modules/vfs/$SO_LIBRARY2)
	fi
	cp $src "$OS_SAMBA_MODULES_DIR/$SO_LIBRARY2"
	chmod 755 "$OS_SAMBA_MODULES_DIR/$SO_LIBRARY2"

	SHARE_DIR="/"
	SMB_CONF_FILE="/etc/samba/smb.conf"
	grep "vfs objects = $BASE_NAME" $SMB_CONF_FILE >> /dev/null
	status=$?
	if [ "$status" -eq 0 ]; then
		echo "Configuration of $PROJECT_NAME already exists in smb.conf."
	else
		echo "Configuring Samba..."
		cat >> $SMB_CONF_FILE << EOF

# $PROJECT_NAME VFS share
[database]
   path = $SHARE_DIR
   vfs objects = $BASE_NAME
   read only = no
   browseable = yes
   $BASE_NAME:connection_string = dbname=myapp user=dbuser password=secret
# Force use pred / pwrite because pread_recv / pread_send / pwrite_send / pwrite_recv are not implemented (lower performances)
   aio read size = 0
   aio write size = 0
EOF
	fi
	# Create directory for the share
	mkdir -p $SHARE_DIR
	# chmod 777 $SHARE_DIR

	echo "Restarting Samba..."
	systemctl restart smbd
}

function install_samba_vfs_service {
	# Install Python dependencies
	docker ps | grep $TRACIM_DOCKER_CONTAINER
	status=$?
	if [ "$status" -ne 0 ]; then
		echo "Starting Tracim docker containers. (it last 1 minute)"
		nohup docker compose up >docker-compose.log 2>&1 &
		sleep 60
	else
		echo "Tracim docker container is already running."
	fi
	echo "Installing Python service in Tracim Docker container..."
	docker cp $SRC_DIR/samba_vfs_service.py $TRACIM_DOCKER_CONTAINER:/tracim/backend/daemons/
	docker cp $SRC_DIR/samba_vfs $TRACIM_DOCKER_CONTAINER:/tracim/backend/tracim_backend/lib/
	docker exec -it $TRACIM_DOCKER_CONTAINER /tracim/backend/tracim_backend/lib/samba_vfs/install.sh
}

function run_samba_vfs_service {
	echo "Starting Python service..."
	docker exec -it $TRACIM_DOCKER_CONTAINER bash -c "export TRACIM_CONF_PATH=/etc/tracim/development.ini;python3 /tracim/backend/daemons/samba_vfs_service.py 2>&1|tee /srv/tmpalb.log"
}

install_deps
load_samba_source
compile_vfs_module
install_vfs_module
install_samba_vfs_service
run_samba_vfs_service

echo "===== Deployment completed ====="
echo "The Samba VFS module has been installed and configured in Tracim."
