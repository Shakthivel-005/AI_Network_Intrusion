#!/usr/bin/env bash
# One-command installer for Kali / Debian / Ubuntu:   sudo ./install.sh
set -euo pipefail
if [ "$EUID" -ne 0 ]; then exec sudo -E bash "$0" "$@"; fi

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST=/opt/nids
REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"

echo "==> [1/6] System packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3 python3-venv python3-pip python3-dev build-essential curl xdg-utils

echo "==> [2/6] Security tools (Wireshark/tshark, Suricata, Zeek, nmap) - optional, failures are OK"
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections || true
apt-get install -y tshark wireshark || echo "   ! tshark/wireshark not installed"
apt-get install -y suricata || echo "   ! suricata not installed"
apt-get install -y nmap hping3 || true
apt-get install -y zeek || echo "   ! zeek is not in this repo (optional - see README for the official Zeek repo)"

echo "==> [3/6] Copying application to $DEST"
mkdir -p "$DEST"
cp -r "$SRC/app.py" "$SRC/nids" "$SRC/requirements.txt" "$DEST/"

echo "==> [4/6] Python virtual environment + libraries (pandas, scikit-learn, streamlit ...)"
python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install --upgrade pip wheel
"$DEST/venv/bin/pip" install -r "$DEST/requirements.txt"

echo "==> [5/6] Launcher + menu entry"
install -m 755 "$SRC/packaging/nids-gui" /usr/local/bin/nids-gui
cat > /usr/share/applications/nids-gui.desktop << DESK
[Desktop Entry]
Name=AI Network Intrusion Detection
Comment=ML-based NIDS and SOC dashboard
Exec=nids-gui
Icon=security-high
Terminal=true
Type=Application
Categories=Network;Security;System;
DESK

echo "==> [6/6] Packet-capture permission for user '$REAL_USER'"
getent group wireshark >/dev/null && usermod -aG wireshark "$REAL_USER" || true

cat << DONE

 Installed.  Start the GUI with:     nids-gui
 Quick non-GUI test:                 nids-gui demo
 (Log out and back in once so live packet capture works without sudo.)
DONE
