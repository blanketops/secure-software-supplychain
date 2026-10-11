#!/usr/bin/env bash
# Lets a kind cluster's nodes download several images at once.
#
# A kubelet pulls one image at a time unless told otherwise, so an install
# that needs sixty images downloads them in a queue. This turns that off on
# every node of a kind cluster that already exists, and restarts the kubelet,
# which takes a few seconds and does not restart any pod.
#
#   hack/kind-parallel-pulls.sh <cluster name>      # default: kind
#   MAX_PARALLEL=4 hack/kind-parallel-pulls.sh <cluster name>
#
# For a new cluster, create it with hack/kind-cluster.yaml instead, which has
# the same setting from the start.
set -euo pipefail

CLUSTER=${1:-kind}
MAX_PARALLEL=${MAX_PARALLEL:-8}
CONFIG=/var/lib/kubelet/config.yaml

nodes=$(kind get nodes --name "$CLUSTER")
if [ -z "$nodes" ]; then
  echo "No kind cluster named \"$CLUSTER\". The clusters are: $(kind get clusters | tr '\n' ' ')" >&2
  exit 1
fi

for node in $nodes; do
  docker exec "$node" sh -c "
    set -e
    grep -v -e '^serializeImagePulls:' -e '^maxParallelImagePulls:' $CONFIG > $CONFIG.new
    printf 'serializeImagePulls: false\nmaxParallelImagePulls: %s\n' '$MAX_PARALLEL' >> $CONFIG.new
    mv $CONFIG.new $CONFIG
    systemctl restart kubelet
  "
  echo "  ✓ $node pulls up to $MAX_PARALLEL images at once"
done

# The kubelet reports the configuration it is running with.
context="kind-$CLUSTER"
for node in $nodes; do
  for _ in $(seq 30); do
    if serial=$(kubectl --context "$context" get --raw "/api/v1/nodes/$node/proxy/configz" 2>/dev/null |
      grep -o '"serializeImagePulls":[a-z]*'); then
      break
    fi
    sleep 2
  done
  echo "  $node: ${serial:-the kubelet has not answered yet}"
done
