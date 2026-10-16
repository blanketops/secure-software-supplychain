#!/usr/bin/env bash
# Add Trillian's database to XAMPP's phpMyAdmin, read-only, and start XAMPP's
# Apache. Run it as yourself; it asks for sudo itself (XAMPP's files belong to
# root and daemon), so the password is only ever typed at sudo's prompt.
#
#   1. Checks the 127.0.0.1:3307 port-forward to trillian-mysql is up (started
#      by gitops/hack/tailnet-links.sh) and starts its user unit if not.
#   2. Backs up phpMyAdmin's config.inc.php once, then adds a server
#      "Trillian (read-only)" on 127.0.0.1:3307 with cookie login, limited to
#      the trillian database. Sign in as trillian_ro (hack/trillian-ui.sh).
#   3. Replaces XAMPP's default cookie passphrase ('xampp'), which phpMyAdmin
#      5.2 rejects as too short for cookie login, with a random 32-character one.
#   4. Turns XAMPP's HTTPS off (Tailscale already listens on 443 here, so
#      Apache would fail to start) and starts, or restarts, Apache.
#
# Safe to run again. -n edits the config only (no service changes, no sudo
# when the directory is writable), for trying it on a copy with -x.
#
# usage: hack/trillian-phpmyadmin.sh [-x xampp-dir] [-n]
set -euo pipefail

xampp=/opt/lampp
config_only=false
while getopts "x:n" opt; do
  case $opt in
    x) xampp=$OPTARG ;;
    n) config_only=true ;;
    *) echo "usage: $0 [-x xampp-dir] [-n]" >&2; exit 2 ;;
  esac
done
config=$xampp/phpmyadmin/config.inc.php
marker="Trillian (kind-blanketops), read-only"
[[ -f $config ]] || { echo "no phpMyAdmin config at $config" >&2; exit 1; }

if [[ $EUID -ne 0 ]] && ! { $config_only && [[ -w $config ]]; }; then
  exec sudo "$0" "$@"
fi

# 1. The port-forward, owned by the invoking user's systemd.
port_up() { timeout 5 bash -c '</dev/tcp/127.0.0.1/3307' 2>/dev/null; }
if ! $config_only && ! port_up; then
  user=${SUDO_USER:-$USER}
  echo "127.0.0.1:3307 is not answering; starting trillian-mysql-port-forward for $user"
  sudo -u "$user" XDG_RUNTIME_DIR="/run/user/$(id -u "$user")" \
    systemctl --user start trillian-mysql-port-forward.service || true
  for _ in $(seq 1 20); do port_up && break; sleep 2; done
  port_up || echo "warning: 127.0.0.1:3307 still closed; run gitops/hack/tailnet-links.sh, then log in" >&2
fi

# 2 and 3. The config, backed up once, checked with PHP before it is kept.
backup=$config.before-trillian
[[ -f $backup ]] || cp -p "$config" "$backup"
before=$(mktemp); cp -p "$config" "$before"

if ! grep -qF "$marker" "$config"; then
  cat >> "$config" <<EOF

/* $marker: Trillian's MySQL through the 127.0.0.1:3307 port-forward.
 * Sign in as trillian_ro; its password is in the trillian-system/
 * trillian-mysql-readonly Secret (see hack/trillian-ui.sh). */
\$i++;
\$cfg['Servers'][\$i]['verbose'] = 'Trillian (read-only)';
\$cfg['Servers'][\$i]['host'] = '127.0.0.1';
\$cfg['Servers'][\$i]['port'] = '3307';
\$cfg['Servers'][\$i]['auth_type'] = 'cookie';
\$cfg['Servers'][\$i]['only_db'] = 'trillian';
EOF
  echo "added the Trillian server to $config"
else
  echo "the Trillian server is already in $config"
fi

if grep -q "^\$cfg\['blowfish_secret'\] = 'xampp';" "$config"; then
  secret=$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)
  sed -i "s|^\$cfg\['blowfish_secret'\] = 'xampp';.*|\$cfg['blowfish_secret'] = '$secret'; /* 32 characters, set by hack/trillian-phpmyadmin.sh */|" "$config"
  unset secret
  echo "replaced the default cookie passphrase"
fi

php=$xampp/bin/php; [[ -x $php ]] || php=php
if ! "$php" -l "$config" >/dev/null; then
  cp -p "$before" "$config"; rm -f "$before"
  echo "the edited config does not parse; put the previous one back" >&2; exit 1
fi
rm -f "$before"

$config_only && { echo "config only (-n): services left as they are"; exit 0; }

# 4. Apache over HTTP only.
"$xampp/lampp" disablessl
if "$xampp/share/xampp/statusraw" | grep -q "APACHE RUNNING"; then
  "$xampp/lampp" restartapache
else
  "$xampp/lampp" startapache
fi

for _ in $(seq 1 15); do
  page=$(curl -s --max-time 5 http://localhost/phpmyadmin/ || true)
  grep -q 'Trillian (read-only)' <<<"$page" && break
  sleep 2
done
if grep -q 'Trillian (read-only)' <<<"$page"; then
  echo
  echo "phpMyAdmin is up: http://localhost/phpmyadmin"
  echo "  server   Trillian (read-only)"
  echo "  user     trillian_ro"
  echo "  password kubectl -n trillian-system get secret trillian-mysql-readonly -o jsonpath='{.data.password}' | base64 -d"
else
  echo "Apache started, but http://localhost/phpmyadmin does not list the Trillian server yet; check $xampp/logs/error_log" >&2
  exit 1
fi
