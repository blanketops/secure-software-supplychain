#!/usr/bin/env bash
# A way to look into Trillian's database, the storage under Rekor's
# transparency log, without being able to change it.
#
#   1. Creates (or re-grants) a MySQL account, trillian_ro, that may only
#      SELECT from the trillian database, and keeps its password in the
#      trillian-system/trillian-mysql-readonly Secret. The password is generated
#      here and never printed.
#   2. Deploys Adminer (hack/trillian-ui/adminer.yaml), a web UI preset to
#      Trillian's MySQL. Sign in with trillian_ro.
#
# Safe to run again: an existing password is kept.
#
# usage: hack/trillian-ui.sh [-c context]
#   the read-only password afterwards:
#   kubectl -n trillian-system get secret trillian-mysql-readonly -o jsonpath='{.data.password}' | base64 -d
set -euo pipefail

context=$(kubectl config current-context)
while getopts "c:" opt; do
  case $opt in
    c) context=$OPTARG ;;
    *) echo "usage: $0 [-c context]" >&2; exit 2 ;;
  esac
done
k() { kubectl --context "$context" -n trillian-system "$@"; }
dir=$(cd "$(dirname "$0")" && pwd)

if k get secret trillian-mysql-readonly >/dev/null 2>&1; then
  password=$(k get secret trillian-mysql-readonly -o jsonpath='{.data.password}' | base64 -d)
else
  password=$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)
  k create secret generic trillian-mysql-readonly \
    --from-literal=username=trillian_ro --from-literal=password="$password" >/dev/null
  k label secret trillian-mysql-readonly app.kubernetes.io/name=trillian-adminer >/dev/null
fi

# The password reaches MySQL on stdin, never on a command line or in a log.
# Only SELECT (and SHOW VIEW) on the trillian database: no writes, no other schema.
k exec -i deploy/trillian-mysql -- sh -c 'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" "$MYSQL_DATABASE" 2>/dev/null' <<SQL
CREATE USER IF NOT EXISTS 'trillian_ro'@'%' IDENTIFIED BY '${password}';
ALTER USER 'trillian_ro'@'%' IDENTIFIED BY '${password}';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'trillian_ro'@'%';
GRANT SELECT, SHOW VIEW ON trillian.* TO 'trillian_ro'@'%';
FLUSH PRIVILEGES;
SQL
unset password

grants=$(k exec deploy/trillian-mysql -- sh -c \
  'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -N -e "SHOW GRANTS FOR trillian_ro@\"%\"" 2>/dev/null')
echo "trillian_ro may:"; sed 's/^/  /' <<<"$grants"

k apply -f "$dir/trillian-ui/adminer.yaml" >/dev/null
k rollout status deployment/trillian-adminer --timeout=600s
echo "Adminer is up: kubectl -n trillian-system port-forward svc/trillian-adminer 8306:8080, then http://localhost:8306"
echo "(server trillian-mysql, user trillian_ro, database trillian; the password is in the trillian-mysql-readonly Secret)"
