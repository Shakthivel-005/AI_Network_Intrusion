#!/usr/bin/env bash
# Builds network-intrusion-detection_1.0.0_all.deb   ->   sudo apt install ./network-intrusion-detection_1.0.0_all.deb
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VER=1.0.0; PKG=network-intrusion-detection
B="$(mktemp -d)/${PKG}_${VER}_all"
mkdir -p "$B/DEBIAN" "$B/opt/nids" "$B/usr/bin" "$B/usr/share/applications"
cp -r "$ROOT/app.py" "$ROOT/nids" "$ROOT/requirements.txt" "$B/opt/nids/"
find "$B/opt/nids" -name __pycache__ -type d -prune -exec rm -rf {} +
install -m 755 "$ROOT/packaging/nids-gui" "$B/usr/bin/nids-gui"
cat > "$B/usr/share/applications/nids-gui.desktop" << D
[Desktop Entry]
Name=AI Network Intrusion Detection
Comment=ML-based NIDS and SOC dashboard
Exec=nids-gui
Icon=security-high
Terminal=true
Type=Application
Categories=Network;Security;System;
D
cat > "$B/DEBIAN/control" << C
Package: $PKG
Version: $VER
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.9), python3-venv, python3-pip, xdg-utils
Recommends: tshark, suricata, nmap
Maintainer: SOC Student <student@localhost>
Description: AI-based network intrusion detection and security monitoring system
 Machine-learning NIDS (Random Forest, Decision Tree, Logistic Regression,
 Isolation Forest) with a Streamlit SOC dashboard, alert management,
 Wireshark/Zeek/Suricata integration and incident report generation.
 Run it with the command: nids-gui
C
cat > "$B/DEBIAN/postinst" << 'P'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
  echo "Creating Python environment for AI-NIDS (needs internet) ..."
  python3 -m venv /opt/nids/venv
  /opt/nids/venv/bin/pip install --upgrade pip wheel || true
  /opt/nids/venv/bin/pip install -r /opt/nids/requirements.txt || \
     echo "WARNING: pip install failed - connect to the internet and run: nids-gui --repair"
  getent group wireshark >/dev/null && [ -n "${SUDO_USER:-}" ] && usermod -aG wireshark "$SUDO_USER" || true
  echo "AI-NIDS installed. Start it with:  nids-gui"
fi
exit 0
P
cat > "$B/DEBIAN/postrm" << 'P'
#!/bin/sh
if [ "$1" = "purge" ] || [ "$1" = "remove" ]; then rm -rf /opt/nids; fi
exit 0
P
chmod 755 "$B/DEBIAN/postinst" "$B/DEBIAN/postrm"
dpkg-deb --build --root-owner-group "$B" "$ROOT/${PKG}_${VER}_all.deb"
echo "Built $ROOT/${PKG}_${VER}_all.deb"
