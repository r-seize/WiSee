#!/bin/bash
set -e

REPO="https://github.com/r-seize/wisee.git"
SYMLINK="/usr/local/bin/wisee"

echo ""
echo "  WiSee - installer"
echo "  =================="
echo ""

if command -v pipx &>/dev/null; then
    echo "  [pipx] Installing..."
    pipx install "git+${REPO}" --force

    # Detect real pipx bin dir instead of assuming ~/.local/bin
    PIPX_BIN="$(pipx environment --value PIPX_BIN_DIR 2>/dev/null || echo "$HOME/.local/bin")"
    WISEE_BIN="${PIPX_BIN}/wisee"

elif command -v pip3 &>/dev/null; then
    echo "  [pip] Installing..."
    pip3 install --user "git+${REPO}" --quiet
    WISEE_BIN="$HOME/.local/bin/wisee"

else
    echo "  ❌ pip3 or pipx required: sudo apt install python3-pip pipx"
    exit 1
fi

# Fallback: search in PATH
if [ ! -f "$WISEE_BIN" ]; then
    WISEE_BIN="$(command -v wisee 2>/dev/null || true)"
fi

if [ ! -f "$WISEE_BIN" ]; then
    echo "  ❌ Binary not found. Try manually:"
    echo "     sudo ln -sf \$(which wisee) /usr/local/bin/wisee"
    exit 1
fi

echo "  [sudo] Creating symlink at $SYMLINK..."
sudo ln -sf "$WISEE_BIN" "$SYMLINK"

echo ""
echo "  ✅ Done! sudo wisee scan is ready."
echo ""