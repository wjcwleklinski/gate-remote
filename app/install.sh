#!/bin/bash
#
# Deploys main.py to the Raspberry Pi and (re)starts the service.
# Run from the laptop. Safe to re-run — this is the redeploy loop.
#
#   PI_HOST=pi@192.168.0.20 bash install.sh
#
set -euo pipefail

PI_HOST="${PI_HOST:-pi@192.168.0.20}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "▶ Copying source to $PI_HOST"
ssh "$PI_HOST" "mkdir -p /tmp/gate-remote-src"
scp "$SCRIPT_DIR"/{main.py,requirements.txt,gate-remote.service,.env.example} \
    "$PI_HOST:/tmp/gate-remote-src/"

echo "▶ Installing on the Pi"
ssh "$PI_HOST" 'sudo bash -s' <<'REMOTE'
set -euo pipefail
SRC=/tmp/gate-remote-src

# python3-lgpio is the backend that can drive the Pi 5's RP1 chip. Installing
# it from apt rather than pip avoids compiling it, which is why the venv below
# is created with --system-site-packages.
apt-get update -qq
apt-get install -y -qq python3-venv python3-gpiozero python3-lgpio

id gate-remote &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin gate-remote
# The gpio group owns /dev/gpiochip*; without it the service cannot open the pin.
getent group gpio >/dev/null && usermod -aG gpio gate-remote

install -d -o gate-remote -g gate-remote /opt/gate-remote
install -d /etc/gate-remote
install -o gate-remote -g gate-remote -m 644 "$SRC/main.py" /opt/gate-remote/main.py

if [[ ! -d /opt/gate-remote/venv ]]; then
  python3 -m venv --system-site-packages /opt/gate-remote/venv
fi
/opt/gate-remote/venv/bin/pip install -q --upgrade pip
/opt/gate-remote/venv/bin/pip install -q -r "$SRC/requirements.txt"

if [[ ! -f /etc/gate-remote/gate-remote.env ]]; then
  install -m 640 -g gate-remote "$SRC/.env.example" /etc/gate-remote/gate-remote.env
  echo "  ! Created /etc/gate-remote/gate-remote.env from the example — review it"
fi

install -m 644 "$SRC/gate-remote.service" /etc/systemd/system/gate-remote.service
systemctl daemon-reload
systemctl enable --now gate-remote
systemctl restart gate-remote
rm -rf "$SRC"
REMOTE

echo "▶ Status"
ssh "$PI_HOST" "systemctl --no-pager --lines=15 status gate-remote"
