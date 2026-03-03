#!/bin/bash
# install.sh — WiSee universal installer
# Usage: bash install.sh
#   or : curl -sSL https://raw.githubusercontent.com/r-seize/wisee/main/install.sh | bash
set -e

REPO="https://github.com/r-seize/wisee.git"
SYMLINK="/usr/local/bin/wisee"

echo ""
echo "  WiSee — installer"
echo "  =================="
echo ""

# --- Detect installation method ---
if command -v pipx &>/dev/null; then
    echo "  [pipx] Installing via pipx..."
    pipx install "git+${REPO}" --force
    WISEE_BIN="$(pipx environment --value PIPX_BIN_DIR 2>/dev/null)/wisee"

    # Fallback if pipx environment command is unavailable
    if [ ! -f "$WISEE_BIN" ]; then
        WISEE_BIN="$HOME/.local/bin/wisee"
    fi

elif command -v pip3 &>/dev/null; then
    echo "  [pip] Installing via pip3..."
    pip3 install --user "git+${REPO}" --quiet
    WISEE_BIN="$HOME/.local/bin/wisee"

else
    echo "  ❌ pip3 or pipx is required. Please install one first:"
    echo "     sudo apt install python3-pip pipx"
    exit 1
fi

# --- Verify binary exists ---
if [ ! -f "$WISEE_BIN" ]; then
    echo "  ❌ Binary not found at: $WISEE_BIN"
    echo "     Try manually: sudo ln -sf \$(which wisee) /usr/local/bin/wisee"
    exit 1
fi

# --- Symlink into /usr/local/bin so sudo wisee works ---
echo "  [sudo] Creating symlink at /usr/local/bin/wisee..."
sudo ln -sf "$WISEE_BIN" "$SYMLINK"

echo ""
echo "  ✅ WiSee installed successfully!"
echo ""
echo "  Usage:"
echo "    sudo wisee scan"
echo "    sudo wisee scan --nmap ports"
echo "    wisee --help"
echo ""