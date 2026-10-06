#!/usr/bin/env bash
# Top pane of demo/4-push-to-build/screenrc: the pods of the build the push
# starts, one line per pipeline step, redrawn whenever one of them changes.
#
# A plain list rather than k9s, and by step rather than by pod name: Tekton
# shortens long pod names to a hash, and the run is named after the
# SupplyChain, which is shown here under the same placeholder as everywhere
# else. Runs that existed before the recording started are left out, so the
# pane is empty until the push lands. It has no AGE column, so it is still
# while nothing happens and the recording's idle-time limit can shorten the
# wait.
: "${APP:?}" "${BRANCH:?}"
NS=${NS:-default}

pods() {
  kubectl get pods -n "$NS" -l tekton.dev/pipelineRun --sort-by=.metadata.creationTimestamp --no-headers \
    -o custom-columns='RUN:.metadata.labels.tekton\.dev/pipelineRun,STEP:.metadata.labels.tekton\.dev/pipelineTask,STATUS:.status.phase' \
    2>/dev/null | grep "^run-${APP}-${BRANCH}-" | grep -v '<none>'
}

before=$(pods | awk '{print $1}' | sort -u)
shown="-"
while true; do
  list=$(pods | grep -v -F -f <(echo "${before:-none}") |
    awk '{printf "%-34s %-28s %s\n", $1, $2, $3}' | sed -e "s#${APP}#your-app#g")
  if [ "$list" != "$shown" ]; then
    shown=$list
    clear
    printf '%-34s %-28s %s\n' "PIPELINERUN" "STEP (one pod each)" "STATUS"
    echo "${list:-  (no build yet)}"
  fi
  sleep 1
done
