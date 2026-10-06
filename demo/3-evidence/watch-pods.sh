#!/usr/bin/env bash
# Top pane of demo/3-evidence/screenrc: the build's pods, redrawn whenever
# one of them changes. A plain list rather than k9s, because the pods are
# named after the SupplyChain and are shown here under the same placeholder as
# everywhere else. It has no AGE column, so the pane is still while nothing
# happens and the recording's idle-time limit can shorten the wait.
: "${APP:?}"
NS=${NS:-default}
shown=""
while true; do
  list=$(kubectl get pods -n "$NS" -l tekton.dev/pipelineRun="run-${APP}-demo" \
    --sort-by=.metadata.creationTimestamp \
    -o custom-columns='POD:.metadata.name,STATUS:.status.phase' 2>/dev/null | sed -e "s#${APP}#your-app#g")
  if [ "$list" != "$shown" ]; then
    shown=$list
    clear
    echo "${list:-POD}"
  fi
  sleep 1
done
