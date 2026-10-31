#!/usr/bin/env bash
# NetLedger installer for systemd-based Linux (Debian/Ubuntu, RHEL/Rocky/Alma, SUSE, ...).
#
#   sudo ./install.sh                          # install the latest release from PyPI
#   sudo ./install.sh /path/to/NetLedger       # install from a source checkout
#   sudo ./install.sh "git+https://github.com/SalamoneJack/NetLedger.git@v1.0.0"
#   sudo ./install.sh --uninstall              # remove the service and program (keeps config + data)
#
# Layout: program in /opt/netledger, config in /etc/netledger, data in /var/lib/netledger,
# service 'netledger' running as the unprivileged 'netledger' user.
set -euo pipefail

PREFIX=/opt/netledger
CONF_DIR=/etc/netledger
DATA_DIR=/var/lib/netledger
SERVICE_USER=netledger
UNIT=/etc/systemd/system/netledger.service
SOURCE="${1:-netledger}"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run as root (sudo $0 $*)"

if [ "${SOURCE}" = "--uninstall" ]; then
  info "Stopping and removing the netledger service"
  systemctl disable --now netledger.service 2>/dev/null || true
  rm -f "${UNIT}" /usr/local/bin/netledger
  systemctl daemon-reload
  rm -rf "${PREFIX}"
  info "Removed. Configuration (${CONF_DIR}) and data (${DATA_DIR}) were kept."
  exit 0
fi

PYTHON="${PYTHON:-python3}"
command -v "${PYTHON}" >/dev/null || fail "python3 not found (install python3 >= 3.9)"
"${PYTHON}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
  || fail "Python 3.9 or newer is required ($("${PYTHON}" --version 2>&1))"
"${PYTHON}" -m venv --help >/dev/null 2>&1 \
  || fail "python venv module missing (Debian/Ubuntu: apt install python3-venv)"
command -v git >/dev/null || info "warning: git not found - install it unless you use git.backend: github"

if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  info "Creating system user ${SERVICE_USER}"
  useradd --system --home-dir "${DATA_DIR}" --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

info "Installing NetLedger into ${PREFIX}"
"${PYTHON}" -m venv "${PREFIX}"
"${PREFIX}/bin/pip" install --quiet --upgrade pip
"${PREFIX}/bin/pip" install --quiet --upgrade "${SOURCE}"
ln -sf "${PREFIX}/bin/netledger" /usr/local/bin/netledger

install -d -m 0750 -o root -g "${SERVICE_USER}" "${CONF_DIR}"
install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${DATA_DIR}"
if [ ! -f "${CONF_DIR}/netledger.yaml" ]; then
  info "Writing starter configuration to ${CONF_DIR}"
  "${PREFIX}/bin/netledger" init "${CONF_DIR}" >/dev/null
  sed -i "s|^# data_dir: .*|data_dir: ${DATA_DIR}|" "${CONF_DIR}/netledger.yaml"
fi
chown root:"${SERVICE_USER}" "${CONF_DIR}"/*.yaml
chmod 0640 "${CONF_DIR}"/*.yaml
chown root:root "${CONF_DIR}/netledger.env"
chmod 0600 "${CONF_DIR}/netledger.env"   # read by systemd (EnvironmentFile), not by the service user

info "Installing systemd unit"
cat > "${UNIT}" <<EOF
[Unit]
Description=NetLedger - network configuration backup and health monitoring
Documentation=https://github.com/SalamoneJack/NetLedger
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
EnvironmentFile=-${CONF_DIR}/netledger.env
Environment=NETLEDGER_CONFIG=${CONF_DIR}/netledger.yaml
Environment=NETLEDGER_DATA_DIR=${DATA_DIR}
Environment=HOME=${DATA_DIR}
ExecStart=${PREFIX}/bin/netledger serve
Restart=on-failure
RestartSec=10
TimeoutStopSec=30

# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${DATA_DIR}
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
CapabilityBoundingSet=
SystemCallArchitectures=native
UMask=0027

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable netledger.service >/dev/null

cat <<EOF

NetLedger installed.

  1. Edit ${CONF_DIR}/netledger.yaml   (git.url, schedules, notifications)
  2. Edit ${CONF_DIR}/inventory.yaml   (your devices)
  3. Put secrets in ${CONF_DIR}/netledger.env (device credentials, GIT_TOKEN)
  4. Check:  sudo netledger -c ${CONF_DIR}/netledger.yaml validate
             sudo netledger -c ${CONF_DIR}/netledger.yaml test -d <device>
  5. Start:  sudo systemctl start netledger && journalctl -u netledger -f
  6. Browse: http://$(hostname -f 2>/dev/null || hostname):8080/

EOF
