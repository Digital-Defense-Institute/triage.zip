#!/usr/bin/env bash
# Decide before building; build scripts must not control publication eligibility.
set -euo pipefail

upstream_changed=false
if [[ ${VELO_VERSION_CHANGED:-false} == true || ${TRIAGE_TARGETS_CHANGED:-false} == true || ${LINUX_TRIAGE_TARGETS_CHANGED:-false} == true ]]; then
  upstream_changed=true
fi

collector_changed=false
if [[ ${GITHUB_EVENT_NAME:?} == push && ${GITHUB_REF:?} == refs/heads/main ]]; then
  # Checkout must include history. Compare the entire push, including deletions
  # and rename sources, rather than only the final commit of a multi-commit push.
  before=${PUSH_BEFORE:?}
  if [[ $before == 0000000000000000000000000000000000000000 ]]; then
    before=$(git hash-object -t tree /dev/null)
  fi
  if git diff --quiet --no-renames "$before" "${GITHUB_SHA:?}" -- \
    build_collector.sh build_collector_macos.sh config/ lib/ scripts/ .github/workflows/ci.yml; then
    :
  else
    status=$?
    if [[ $status != 1 ]]; then
      echo 'Error: unable to compare collector inputs for publication' >&2
      exit "$status"
    fi
    collector_changed=true
  fi
fi

build=false
case "$GITHUB_EVENT_NAME" in
  push|pull_request|workflow_dispatch) build=true ;;
  schedule) build=$upstream_changed ;;
esac

publish=false
if [[ ${GITHUB_REF:?} == refs/heads/main && $build == true && $GITHUB_EVENT_NAME != pull_request ]]; then
  if [[ $upstream_changed == true || $collector_changed == true || $GITHUB_EVENT_NAME == workflow_dispatch ]]; then
    publish=true
  fi
fi
printf 'build=%s\npublish=%s\n' "$build" "$publish"
