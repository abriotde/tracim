#!/bin/bash
#
# Deployment script for Database VFS module and Python service
#

set -e

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

SMB_MODULES_DIR="$SAMBA_SOURCE/source3/modules"

# Create directories if they don't exist
mkdir -p "$PYTHON_SERVICE_DIR"
touch "$LOG_FILE"
chmod 666 "$LOG_FILE"

# Install dependencies
echo "Installing dependencies..."
apt-get update
apt install -y build-essential libjson-c-dev \
	samba-dev libsmbclient-dev \
	python3-dev python3-pip  \
	liblmdb-dev lmdb-utils libgpgme11-dev libparse-yapp-perl \
	libjansson-dev libarchive-dev
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
  libjansson-dev

# Load Samba source directory
# wget https://download.samba.org/pub/samba/samba-latest.tar.gz
# tar -xvf samba-latest.tar.gz
# samba-4.22.2
git submodule update --init --recursive
if [ ! -d "$SAMBA_SOURCE" ]; then
    echo "Error: Samba source directory not found at: $SAMBA_SOURCE"
    echo "Please update the SAMBA_SOURCE variable in this script."
    exit 1
fi

echo "Compile VFS module..."

cp $SRC_DIR/$VFS_C_SOURCE $SMB_MODULES_DIR/

grep "$PROJECT_NAME" $SMB_MODULES_DIR/../wscript > /dev/null
if [ $status -eq 0 ]; then
	echo "Module $PROJECT_NAME already exists in wscript."
else
	echo "Adding module $PROJECT_NAME to wscript."
	sed -i "/default_shared_modules.extend.*vfs_recycle/ s/$/ \'$PROJECT_NAME\',/" $SMB_MODULES_DIR/../wscript
fi

grep "$PROJECT_NAME" $SMB_MODULES_DIR/wscript_build > /dev/null
status=$?
if [ $status -eq 0 ]; then
	echo "Module $PROJECT_NAME already exists in wscript_build."
else
	echo "Adding module $PROJECT_NAME to wscript_build."
	cat >>$SMB_MODULES_DIR/wscript_build <<EOF

bld.SAMBA3_MODULE('$PROJECT_NAME',
                 subsystem='vfs',
                 source='$VFS_C_SOURCE',
                 deps='samba-util json-c',
                 init_function='',
				 internal_module=False,
                # internal_module=bld.SAMBA3_IS_STATIC_MODULE('$PROJECT_NAME'),
                 enabled=bld.SAMBA3_IS_ENABLED_MODULE('$PROJECT_NAME'))
EOF
fi

echo "Compiling VFS module..."
cd $SAMBA_SOURCE
# ./configure.developer --enable-debug # --without-ldb-lmdb
./configure
make # $PROJECT_NAME.so

# ./bin/default/source3/modules/libvfs_module_db_tracim.so
# ./bin/modules/vfs/db_tracim.so
SO_LIBRARY="libvfs_module_$BASE_NAME.so"
SO_LIBRARY2="$BASE_NAME.so"

# Install Python dependencies
echo "Installing Python dependencies..."
# TODO : venv : pip3 install typing json

# Check if your database library needs to be installed
# pip3 install your-database-library

# Compile the VFS module
make -C "$SRC_DIR"
if [ $? -ne 0 ]; then
  echo "Failed to compile the VFS module"
  exit 1
fi

# Install the VFS module
echo "Installing VFS module..."
cp ./bin/modules/vfs/$SO_LIBRARY "$OS_SAMBA_MODULES_DIR/"
chmod 755 "$OS_SAMBA_MODULES_DIR/$SO_LIBRARY"

# Install the Python service
echo "Installing Python service..."
cp vfs_tracim_service.py "$PYTHON_SERVICE_DIR/"
chmod 755 "$PYTHON_SERVICE_DIR/vfs_tracim_service.py"

# Create systemd service for Python service
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

# Configure Samba
echo "Configuring Samba..."
cat >> /etc/samba/smb.conf << EOF

# Database VFS share
[database]
   path = /var/lib/samba/database
   vfs objects = db_vfs
   read only = no
   browseable = yes
EOF

# Create directory for the share
mkdir -p /var/lib/samba/database
chmod 777 /var/lib/samba/database

# Enable and start the Python service
echo "Starting Python service..."
systemctl daemon-reload
systemctl enable vfs_tracim_service
systemctl start vfs_tracim_service

# Restart Samba
echo "Restarting Samba..."
systemctl restart smbd

echo "===== Deployment completed ====="
echo "The Database VFS module has been installed and configured."
echo "The Python service is running as a systemd service."
echo "Samba has been configured with a [database] share."
echo ""
echo "To check the status of the Python service:"
echo "  systemctl status vfs_tracim_service"
echo ""
echo "To view logs:"
echo "  tail -f $LOG_FILE"
echo ""
echo "To test the share, connect to:"
echo "  \\\\<server-ip>\\database"
echo ""
echo "Customize the Python service to integrate with your database."
