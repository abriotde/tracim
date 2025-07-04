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
SAMBA_MODULES_DIR="/usr/lib/x86_64-linux-gnu/samba/vfs/"
PYTHON_SERVICE_DIR="/usr/local/lib/$PROJECT_NAME"
SOCKET_PATH="/var/run/$PROJECT_NAME.sock"
LOG_FILE="/var/log/$PROJECT_NAME.log"
SYSTEMD_SERVICE_FILE="/etc/systemd/system/$PROJECT_NAME.service"
OS_SAMBA_MODULES_DIR="/usr/lib/x86_64-linux-gnu/samba/vfs"
SMB_MODULES_DIR="$SAMBA_SOURCE/source3/modules"

# Create directories if they don't exist
mkdir -p "$PYTHON_SERVICE_DIR"
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
		libjansson-dev libarchive-dev > /dev/null 2>&1
	apt install -y \
	build-essential \
	python3-dev \
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
	git submodule update --init --recursive
	if [ ! -d "$SAMBA_SOURCE" ]; then
		echo "Error: Samba source directory not found at: $SAMBA_SOURCE"
		echo "Please update the SAMBA_SOURCE variable in this script."
		exit 1
	fi
}

function compile_vfs_module {
	echo "Compile VFS module..."
	# echo "EXEC: cp $SRC_DIR/$VFS_C_SOURCE $SMB_MODULES_DIR/"
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
                deps='samba-util jansson',
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

	echo "Compiling VFS module..."
	cd $SAMBA_SOURCE
	# ./configure.developer --enable-debug # --without-ldb-lmdb
	./configure
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
	cp $SAMBA_SOURCE/bin/modules/vfs/$SO_LIBRARY2 "$OS_SAMBA_MODULES_DIR/"
	chmod 755 "$OS_SAMBA_MODULES_DIR/$SO_LIBRARY2"


	SHARE_DIR="/var/lib/samba/$BASE_NAME"
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
EOF
	fi
	# Create directory for the share
	mkdir -p $SHARE_DIR
	chmod 777 $SHARE_DIR

	echo "Restarting Samba..."
	systemctl restart smbd
}

function install_python_deps {
	# Install Python dependencies
	echo "Installing Python dependencies..."
	# TODO : venv : pip3 install typing json

	# Check if your database library needs to be installed
	# pip3 install your-database-library

	# Install Python dependencies
	pip3 install --upgrade pip
	pip3 install json
	# Add any other dependencies your Python service requires here
}
function install_python_service {
	echo "Installing Python service..."
	cp vfs_tracim_service.py "$PYTHON_SERVICE_DIR/"
	chmod 755 "$PYTHON_SERVICE_DIR/vfs_tracim_service.py"

	echo "Creating systemd service..."
cat > "$SYSTEMD_SERVICE_FILE" << EOF
[Unit]
Description=Database VFS Service for Samba
After=network.target

[Service]
ExecStart=/usr/bin/python3 $PYTHON_SERVICE_DIR/vfs_tracim_service.py
Restart=on-failure
User=root
Group=root
Type=simple

[Install]
WantedBy=multi-user.target
EOF
}

# install_deps
# load_samba_source
# compile_vfs_module
install_vfs_module
exit 0
install_python_deps
install_python_service
start_python_service

function start_python_service {
	echo "Starting Python service..."
	systemctl daemon-reload
	systemctl enable vfs_tracim_service
	systemctl start vfs_tracim_service
}


echo "===== Deployment completed ====="
echo "The VFS module has been installed and configured."
echo "The Python service is running as a systemd service."
echo "Samba has been configured with a [database] share."
echo ""
echo "To check the status of the Python service:"
echo "  systemctl status ${PROJECT_NAME}_service"
echo ""
echo "To view logs:"
echo "  tail -f $LOG_FILE"
echo ""
echo "To test the share, connect to:"
echo ""
