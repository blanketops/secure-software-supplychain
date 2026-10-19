#!/usr/bin/env bash
# Expose the two clusters' UIs and APIs on this machine's Tailscale name, and
# check them. Each link is a kubectl port-forward on 127.0.0.1, kept alive by a
# user systemd unit, served tailnet-only over HTTPS by `tailscale serve` on its
# own port. The only public (Funnel) entry is the GitHub webhook on 443, which
# the solution's installer owns; this script only checks it. Safe to run again:
# unchanged units are not restarted.
#
# usage: hack/tailnet-links.sh [-b build-context] [-r read-context] [-H host] [install|check]
#   -b  build cluster context  (default: kind-software-eng-write)
#   -r  read cluster context   (default: kind-software-eng-read)
#   -H  Tailscale DNS name     (default: this node's, from `tailscale status`)
#   -s  supplychain binary     (default: bin/supplychain of this repository)
#   install (default) writes the units and serve entries, then runs check.
#   check prints every link with the HTTP status it answers with now.
#
# Needs the caller to be the Tailscale operator (once: sudo tailscale set --operator=$USER).
set -euo pipefail

build=kind-software-eng-write
read=kind-software-eng-read
host=""
supplychain=$(cd "$(dirname "$0")/../.." && pwd)/bin/supplychain
while getopts "b:r:H:s:" opt; do
  case $opt in
    b) build=$OPTARG ;;
    r) read=$OPTARG ;;
    H) host=$OPTARG ;;
    s) supplychain=$OPTARG ;;
    *) echo "usage: $0 [-b build-context] [-r read-context] [-H host] [-s supplychain] [install|check]" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
mode=${1:-install}
[[ -n $host ]] || host=$(tailscale status --self --json | jq -r '.Self.DNSName | rtrimstr(".")')

# name | cluster | namespace | target | port-forward ports | serve port (- = this machine only) | local scheme | health path | what
links=(
  "argocd|$read|argocd|svc/argocd-server|8081:443|8081|https|/|Argo CD (read cluster)"
  # Tornjak stays on this machine: its API creates and deletes SPIRE entries
  # without a login and allows any origin, so on the tailnet any page open in
  # a browser there could register an identity. Publish it only behind an
  # authenticating proxy.
  "tornjak|$build|spire-server|svc/tornjak|3000:3000 10000:10000|-|http|/|Tornjak UI (SPIRE)"
  "tekton-dashboard|$build|tekton-pipelines|svc/tekton-dashboard|9097:9097|9097|http|/|Tekton Dashboard"
  "sonarqube|$build|sonarqube-system|svc/sonarqube-sonarqube|9000:9000|9000|http|/sonarqube/|SonarQube"
  "rekor|$build|rekor-system|svc/rekor-server|3443:443|3443|https|/api/v1/log|Rekor API"
  # Adminer has its own login; hack/trillian-ui.sh gives it a read-only account.
  "trillian-ui|$build|trillian-system|svc/trillian-adminer|8306:8080|8306|http|/|Trillian database (Adminer)"
  # Trillian's MySQL itself, for a local client (mysql, phpMyAdmin, DBeaver).
  # Raw MySQL, so this machine only; sign in as trillian_ro (hack/trillian-ui.sh).
  "trillian-mysql|$build|trillian-system|svc/trillian-mysql|3307:3306|-|tcp||Trillian MySQL (read-only login)"
  # Not a port-forward: `supplychain observe` runs its own kubectl proxy and
  # forwards only the page's reads, so it is safe to serve on the tailnet.
  "observer|$build|-|observe|8002|8002|http|/|Supply chain observer (build cluster)"
)

local_port() { local p=${2%%:*}; echo "${p%% *}"; }

install() {
  local bin=$HOME/.local/bin units=$HOME/.config/systemd/user
  mkdir -p "$bin" "$units"
  # kubectl port-forward keeps running after its pod is replaced but forwards
  # nothing, so Restart=always alone never fires: exit when the port stops answering.
  cat > "$bin/kpf-watch" <<'EOF'
#!/usr/bin/env bash
# kpf-watch <health-url> <port-forward command...>: exit when the forward
# stops answering (3 failed checks, 15s apart) so systemd restarts it.
set -u
url=$1; shift
"$@" &
pf=$!
trap 'kill $pf 2>/dev/null' EXIT TERM INT
sleep 10
fails=0
while kill -0 "$pf" 2>/dev/null; do
  if [[ $url == tcp://* ]]; then
    hp=${url#tcp://}; ok() { timeout 5 bash -c "</dev/tcp/${hp%:*}/${hp##*:}" 2>/dev/null; }
  else
    ok() { curl -sk -o /dev/null --max-time 5 "$url"; }
  fi
  if ok; then fails=0; else
    fails=$((fails + 1))
    [ "$fails" -ge 3 ] && { echo "kpf-watch: $url unreachable 3 times, restarting" >&2; exit 1; }
  fi
  sleep 15
done
exit 1
EOF
  chmod +x "$bin/kpf-watch"

  local changed=()
  for l in "${links[@]}"; do
    IFS='|' read -r name ctx ns target ports serve scheme path what <<<"$l"
    [[ $ctx == - ]] && continue
    local lp unit new exec
    lp=$(local_port "$name" "$ports")
    unit=$units/$name-port-forward.service
    exec="$bin/kpf-watch $scheme://127.0.0.1:$lp$path /usr/bin/env kubectl --context $ctx port-forward --address 127.0.0.1 -n $ns $target $ports"
    if [[ $target == observe ]]; then
      [[ -x $supplychain ]] || { echo "no supplychain binary at $supplychain (build it: go build -o bin/supplychain ./cmd/cli)" >&2; exit 1; }
      # It exits when its kubectl proxy or server dies, so systemd alone restarts it.
      unit=$units/supplychain-observe.service
      exec="$supplychain observe --context $ctx --no-browser"
    fi
    new=$(cat <<EOF
[Unit]
Description=$what ($scheme://127.0.0.1:$lp) from $ctx
After=network-online.target

[Service]
Environment=PATH=/usr/local/bin:/usr/bin:/bin
ExecStart=$exec
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
)
    if [[ ! -f $unit || $(cat "$unit") != "$new" ]]; then
      printf '%s\n' "$new" > "$unit"
      changed+=("$(basename "$unit")")
    fi
  done
  systemctl --user daemon-reload
  for l in "${links[@]}"; do
    IFS='|' read -r name ctx _ target _ <<<"$l"
    [[ $ctx == - ]] && continue
    if [[ $target == observe ]]; then
      systemctl --user enable --now supplychain-observe.service 2>/dev/null
    else
      systemctl --user enable --now "$name-port-forward.service" 2>/dev/null
    fi
  done
  ((${#changed[@]})) && systemctl --user restart "${changed[@]}"

  for l in "${links[@]}"; do
    IFS='|' read -r name _ _ _ ports serve scheme _ <<<"$l"
    if [[ $serve == - ]]; then
      # Take it off the tailnet if an earlier version of this script served it.
      [[ $name == tornjak ]] && { tailscale serve --https=3000 off || true; tailscale serve --https=10000 off || true; } >/dev/null 2>&1
      continue
    fi
    local backend=http
    [[ $scheme == https ]] && backend=https+insecure
    tailscale serve --bg --https="$serve" "$backend://127.0.0.1:$(local_port "$name" "$ports")" >/dev/null
  done
  sleep 10
}

check() {
  printf '%-40s %-48s %s\n' WHAT URL STATUS
  local code relay
  # The webhook answers 202 to any JSON POST; the EventListener's interceptor
  # then drops it for want of a GitHub signature, so nothing is built. On this
  # machine MagicDNS resolves the name to the tailnet address, which passes
  # even when Funnel is down, so go through the public relay that GitHub uses.
  relay=$(curl -s --max-time 10 -H 'accept: application/dns-json' \
    "https://1.1.1.1/dns-query?name=$host&type=A" | jq -r '.Answer[0].data // empty' || true)
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 ${relay:+--resolve "$host:443:$relay"} \
    -X POST -H 'Content-Type: application/json' -d '{}' "https://$host/" || true)
  printf '%-40s %-48s %s\n' "GitHub webhook (public, Funnel)" "https://$host/ via ${relay:-no public DNS}" "$code"
  for l in "${links[@]}"; do
    IFS='|' read -r name _ _ _ ports serve scheme path what <<<"$l"
    if [[ $serve == - ]]; then
      local u="$scheme://127.0.0.1:$(local_port "$name" "$ports")$path"
      if [[ $scheme == tcp ]]; then
        local hp=${u#tcp://}
        timeout 5 bash -c "</dev/tcp/${hp%:*}/${hp##*:}" 2>/dev/null && code=open || code=closed
      else
        code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 "$u" || true)
      fi
      printf '%-40s %-48s %s\n' "$what (this machine)" "$u" "$code"
      continue
    fi
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "https://$host:$serve$path" || true)
    printf '%-40s %-48s %s\n' "$what (tailnet)" "https://$host:$serve$path" "$code"
  done
}

case $mode in
  install) install; check ;;
  check) check ;;
  *) echo "unknown mode: $mode" >&2; exit 2 ;;
esac
