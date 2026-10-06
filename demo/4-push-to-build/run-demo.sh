#!/usr/bin/env bash
# Scripted demo run for the bottom pane of demo/4-push-to-build/screenrc.
# Not meant to be run standalone outside that layout (it calls `screen -X
# quit` at the end to stop the whole recording session, pod pane included).
#
# It pushes one empty commit to a branch of a repository a SupplyChain builds,
# and then only watches: nothing after the push is started by hand.
#
#   APP=<supplychain> REPO=docker.io/<user>/<app> GIT_REPO=<org>/<repo> \
#   BRANCH=<branch> CLONE=<path to a clone you can push from> asciinema rec ...
#
# The push and the build are real. The image repository, the git repository
# and the SupplyChain's name are shown as the placeholders this project's
# documentation uses; mask() is the only thing that changes what is displayed.
set -uo pipefail
: "${APP:?}" "${REPO:?}" "${GIT_REPO:?}" "${BRANCH:?}" "${CLONE:?}"

NS=${NS:-default}
ADMISSION_NS=admission-demo

mask() {
  sed -e "s#${REPO#docker.io/}#your-dockerhub-user/your-app#g" -e "s#${GIT_REPO}#your-org/your-app#g" \
    -e "s#${APP}#your-app#g"
}

step() {
  echo
  echo "### $1"
  echo
  sleep 2
}

echo "============================================================"
echo " Demo 4: from a push to a running, verified image"
echo
echo " One 'git push'. GitHub delivers it to the cluster, a build"
echo " starts on its own, and the image it produces is signed,"
echo " logged and admitted. Nothing after the push is run by hand"
echo " except the last command, which deploys the result."
echo "============================================================"
sleep 4

kubectl delete pod pushed-and-built -n "$ADMISSION_NS" --ignore-not-found >/dev/null 2>&1

step "a commit, and a push"
cd "$CLONE" || exit 1
echo "\$ git commit --allow-empty -m 'Trigger the supply chain'"
git commit -q --allow-empty -m 'Trigger the supply chain'
sha=$(git rev-parse HEAD)
git log --oneline -1
echo
echo "\$ git push origin ${BRANCH}"
git push origin "$BRANCH" 2>&1 | mask
BUILD=${APP}-${BRANCH}-${sha}
RUN=run-${APP}-${BRANCH}-${sha:0:8}
sleep 2

step "GitHub delivers the push to the cluster, and an ImageBuild appears"
for _ in $(seq 1 60); do
  kubectl get imagebuild "$BUILD" -n "$NS" >/dev/null 2>&1 && break
  sleep 1
done
if ! kubectl get imagebuild "$BUILD" -n "$NS" >/dev/null 2>&1; then
  echo "  no ImageBuild appeared; the webhook did not reach the cluster"
  sleep 5
  screen -X quit
  exit 1
fi
kubectl get imagebuild "$BUILD" -n "$NS" \
  -o jsonpath='{"  name:      "}{.metadata.name}{"\n  revision:  "}{.spec.gitRef.revision}{"\n  commit:    "}{.metadata.annotations.blanketops\.dev/git-commit-sha}{"\n"}' | mask
sleep 3

step "the pipeline it started: nine steps, each a pod (top pane)"
for _ in $(seq 1 60); do
  steps=$(kubectl get pipelinerun "$RUN" -n "$NS" -o jsonpath='{.spec.pipelineSpec.tasks[*].name}' 2>/dev/null)
  [ -n "$steps" ] && break
  [ "$(kubectl get imagebuild "$BUILD" -n "$NS" -o jsonpath='{.status.phase}' 2>/dev/null)" = Failed ] && break
  sleep 2
done
state=""
for task in $steps; do
  for _ in $(seq 1 300); do
    reason=$(kubectl get taskrun -n "$NS" -l "tekton.dev/pipelineRun=${RUN},tekton.dev/pipelineTask=${task}" \
      -o jsonpath='{.items[0].status.conditions[0].reason}' 2>/dev/null)
    case "$reason" in Succeeded|Failed|TaskRunTimeout|TaskRunCancelled) break ;; esac
    state=$(kubectl get pipelinerun "$RUN" -n "$NS" -o jsonpath='{.status.conditions[0].status}' 2>/dev/null)
    [ "$state" = False ] && break 2
    sleep 2
  done
  printf '  %-28s %s\n' "$task" "$reason"
done
for _ in $(seq 1 60); do
  state=$(kubectl get pipelinerun "$RUN" -n "$NS" -o jsonpath='{.status.conditions[0].status}' 2>/dev/null)
  [ "$state" = True ] || [ "$state" = False ] && break
  sleep 2
done
if [ "$state" != True ]; then
  echo "  the build did not succeed; nothing to show"
  sleep 5
  screen -X quit
  exit 1
fi
sleep 2

step "signed by the build, logged in Rekor, recorded"
for _ in $(seq 1 30); do
  [ "$(kubectl get imagesignature "$BUILD" -n "$NS" -o jsonpath='{.status.phase}' 2>/dev/null)" = Signed ] && break
  sleep 2
done
kubectl get imagesignature "$BUILD" -n "$NS" \
  -o jsonpath='{"  image:       "}{.spec.image}{"\n  digest:      "}{.spec.digest}{"\n  signer:      "}{.status.subject}{"\n  rekor index: "}{.status.rekorLogIndex}{"\n  phase:       "}{.status.phase}{"\n"}' | mask
image=$(kubectl get imagesignature "$BUILD" -n "$NS" -o jsonpath='{.spec.image}')
sleep 5

step "and it may run: the admission policy accepts it"
echo "\$ kubectl run pushed-and-built --image=${image}" | mask
# The webhook fails closed after ten seconds. It reads the image's signatures
# from the registry for each policy, so a slow link can run it out of time;
# asking again is all there is to do.
for attempt in 1 2 3 4 5; do
  out=$(kubectl run pushed-and-built -n "$ADMISSION_NS" --restart=Never --image="$image" 2>&1)
  echo "$out" | grep -q 'context deadline exceeded' || break
  echo "  (the admission webhook ran out of time reading the registry; asking again)"
  sleep 2
done
echo "$out" | mask
kubectl wait --for=condition=Ready pod/pushed-and-built -n "$ADMISSION_NS" --timeout=120s >/dev/null 2>&1
kubectl get pod pushed-and-built -n "$ADMISSION_NS"
sleep 4

step "demo done"
sleep 4

screen -X quit
