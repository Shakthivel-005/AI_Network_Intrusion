#!/usr/bin/env bash
[ "$EUID" -ne 0 ] && exec sudo bash "$0"
rm -rf /opt/nids /usr/local/bin/nids-gui /usr/share/applications/nids-gui.desktop
echo "Removed. Your data in ~/.nids was kept (delete it manually if you want)."
