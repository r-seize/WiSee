#!/bin/bash
# build_deb.sh — Build a .deb package for WiSee
# Usage: bash build_deb.sh
set -e

VERSION="0.1.1"
PACKAGE_NAME="wisee"
BUILD_DIR="deb_dist/${PACKAGE_NAME}_${VERSION}_all"
INSTALL_PREFIX="/usr/local"

# Detect the actual Python version on the target system
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYTHON_SITE="${INSTALL_PREFIX}/lib/python${PYTHON_VERSION}/dist-packages"

echo "Building WiSee v${VERSION} .deb package..."
echo "  Python version : ${PYTHON_VERSION}"
echo "  Install site   : ${PYTHON_SITE}"

# Clean previous build
rm -rf deb_dist
mkdir -p "${BUILD_DIR}/DEBIAN"
mkdir -p "${BUILD_DIR}${PYTHON_SITE}"
mkdir -p "${BUILD_DIR}${INSTALL_PREFIX}/bin"

# Copy Python package
cp -r src/wisee "${BUILD_DIR}${PYTHON_SITE}/"

# Create the wisee wrapper script
# sys.path.insert ensures the module is found even if site-packages
# is not in the default python3 system path
cat > "${BUILD_DIR}${INSTALL_PREFIX}/bin/wisee" <<SCRIPT
#!/usr/bin/env python3
import sys
sys.path.insert(0, "${PYTHON_SITE}")
from wisee.cli import cli
if __name__ == "__main__":
    cli()
SCRIPT
chmod +x "${BUILD_DIR}${INSTALL_PREFIX}/bin/wisee"

# DEBIAN/control
cat > "${BUILD_DIR}/DEBIAN/control" <<EOF
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: all
Maintainer: WiSee <https://github.com/r-seize/wisee>
Depends: python3 (>= 3.10), python3-pip
Recommends: nmap
Description: Local network discovery tool
 WiSee scans your LAN via ARP broadcast, enriches results with
 mDNS, NetBIOS, UPnP and banner grabbing, and optionally runs
 deep nmap recon on each discovered host.
 .
 Usage: sudo wisee scan
EOF

# DEBIAN/postinst — install Python dependencies after package install
cat > "${BUILD_DIR}/DEBIAN/postinst" <<'EOF'
#!/bin/bash
set -e

# Install Python dependencies
pip3 install --quiet --break-system-packages scapy rich click 2>/dev/null || \
pip3 install --quiet scapy rich click 2>/dev/null || true

echo "WiSee installed successfully. Run: sudo wisee scan"
EOF
chmod 0755 "${BUILD_DIR}/DEBIAN/postinst"

# Build the .deb package
dpkg-deb --build "${BUILD_DIR}" "deb_dist/${PACKAGE_NAME}_${VERSION}_all.deb"

echo ""
echo "✅  .deb created: deb_dist/${PACKAGE_NAME}_${VERSION}_all.deb"
echo ""
echo "Install with:"
echo "  sudo dpkg -i deb_dist/${PACKAGE_NAME}_${VERSION}_all.deb"
echo ""
echo "Then run:"
echo "  sudo wisee scan"