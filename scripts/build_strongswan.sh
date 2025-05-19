#!/bin/bash
set -e  # Exit on error

# Default configuration
STRONGSWAN_VERSION="6.0.0beta6"
INSTALL_PREFIX="/usr"
WORK_DIR="/tmp/strongswan-build"
SRC_DIR="$WORK_DIR/strongswan"

# Parse command line arguments
while getopts "v:h" opt; do
  case $opt in
    v) STRONGSWAN_VERSION="$OPTARG"
       ;;
    h) echo "Usage: $0 [-v version]"
       echo "  -v version    strongSwan version to checkout (default: $STRONGSWAN_VERSION)"
       echo "  -h            Display this help message"
       exit 0
       ;;
    \?) echo "Invalid option: -$OPTARG" >&2
       exit 1
       ;;
  esac
done

echo "Building strongSwan from GitHub (Version: $STRONGSWAN_VERSION)..."

# Check if strongSwan directory exists
if [ -d "$SRC_DIR" ]; then
    echo "The directory $SRC_DIR already exists."
    read -p "Would you like to remove it and clone a fresh copy? (y/n): " answer
    if [ "$answer" = "y" ]; then
        echo "Removing existing directory..."
        rm -rf "$SRC_DIR"
    else
        echo "Aborting. Please manually handle the existing directory."
        exit 1
    fi
fi

# Create working directory
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

# Install minimal build dependencies (if needed)
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    libgmp-dev \
    libssl-dev \
    automake \
    autoconf \
    libtool \
    pkg-config \
    git

# Clone strongSwan from GitHub
git clone https://github.com/strongswan/strongswan.git
cd "$SRC_DIR"

# Checkout the specified version
echo "Attempting to checkout: $STRONGSWAN_VERSION"
if git tag | grep -q "^$STRONGSWAN_VERSION$"; then
    git checkout "$STRONGSWAN_VERSION"
    echo "Successfully checked out tag: $STRONGSWAN_VERSION"
else
    echo "Warning: Tag $STRONGSWAN_VERSION not found."
    echo "Available tags:"
    git tag | grep -i "6.0.0" || echo "No tags containing 6.0.0 found."
    
    read -p "Would you like to continue with the main branch? (y/n): " continue_answer
    if [ "$continue_answer" != "y" ]; then
        echo "Aborting."
        exit 1
    fi
fi

# Generate configure script using autogen.sh
echo "Generating configure script..."
if [ -f "./autogen.sh" ]; then
    chmod +x ./autogen.sh
    ./autogen.sh
elif [ -f "./configure.ac" ]; then
    autoreconf -i
else
    echo "Neither autogen.sh nor configure.ac found. Repository structure:"
    ls -la
    echo "Aborting."
    exit 1
fi

# Verify configure script exists now
if [ ! -f "./configure" ]; then
    echo "Failed to generate configure script. Checking repository structure..."
    ls -la
    echo "Aborting."
    exit 1
fi

# Configure with minimal options but include dev headers
./configure \
    --prefix=$INSTALL_PREFIX \
    --sysconfdir=/etc \
    --with-dev-headers=$INSTALL_PREFIX/include/strongswan \
    --disable-defaults \
    --enable-openssl \
    --enable-pem \
    --enable-pkcs1 \
    --enable-pkcs8 \
    --enable-x509 \
    --enable-pubkey \
    --enable-oqs \
    --enable-nonce \
    --enable-random \
    --enable-kernel-netlink \
    --enable-socket-default \
    --enable-vici \
    --enable-swanctl \
    --enable-charon \
    --enable-ikev2

# Build and install
make -j$(nproc)
sudo make install

echo "---------------------------------------------"
echo "strongSwan installed with development headers."
echo "Development headers: $INSTALL_PREFIX/include/strongswan"
echo "Now you can build your external QKD plugins."