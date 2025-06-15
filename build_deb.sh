#!/bin/bash

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Starting Debian package build process...${NC}"

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${RED}Please do not run this script as root${NC}"
    exit 1
fi

# Function to install dependencies
install_dependencies() {
    echo -e "${YELLOW}Installing required build tools...${NC}"
    sudo apt update
    sudo apt install -y devscripts debhelper python3-all python3-setuptools dh-python
}

# Check for required tools and install if missing
echo -e "${YELLOW}Checking for required tools...${NC}"
missing_tools=()
for cmd in debuild dpkg-buildpackage; do
    if ! command -v $cmd &> /dev/null; then
        missing_tools+=("$cmd")
    fi
done

if [ ${#missing_tools[@]} -ne 0 ]; then
    echo -e "${YELLOW}Missing tools: ${missing_tools[*]}${NC}"
    install_dependencies
fi

# Verify installation
echo -e "${YELLOW}Verifying tool installation...${NC}"
for cmd in debuild dpkg-buildpackage; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "${RED}Failed to install $cmd${NC}"
        exit 1
    fi
done

# Update changelog with current date
echo -e "${YELLOW}Updating changelog...${NC}"
sed -i "s/\$(date -R)/$(date -R)/" debian/changelog

# Clean previous build
echo -e "${YELLOW}Cleaning previous build...${NC}"
rm -rf build/ dist/ *.egg-info/ debian/python3-ossec-config-manager/
rm -f ../python3-ossec-config-manager_*.deb ../python3-ossec-config-manager_*.dsc ../python3-ossec-config-manager_*.tar.gz ../python3-ossec-config-manager_*.changes

# Build the package
echo -e "${YELLOW}Building Debian package...${NC}"
debuild -us -uc

# Check if build was successful
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Package built successfully!${NC}"
    echo -e "${YELLOW}Package files:${NC}"
    ls -l ../python3-ossec-config-manager_*.deb
    echo -e "\n${YELLOW}To install the package:${NC}"
    echo "sudo apt install ./python3-ossec-config-manager_*.deb"
else
    echo -e "${RED}Package build failed!${NC}"
    exit 1
fi