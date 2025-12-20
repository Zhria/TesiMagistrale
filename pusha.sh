#!/bin/bash

COMMIT_MSG="push automatico"
BUILD_IMAGES=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build|-n)
      BUILD_IMAGES=false
      shift
      ;;
    *)
      COMMIT_MSG="$*"
      break
      ;;
  esac
done

if $BUILD_IMAGES; then
  declare -a TAGS=(
    "zhria/n3iwfcustom:latest"
    "zhria/amfcustom:latest"
    "zhria/smfcustom:latest"
    "zhria/e2node:latest"
  )
  declare -a DOCKERFILES=(
    "./n3iwfCustom/Dockerfile"
    "./amfCustom/Dockerfile"
    "./smfCustom/Dockerfile"
    "./e2sim/Dockerfile"
  )
  declare -a CONTEXTS=(
    "."         # n3iwfCustom Dockerfile expects repo-root context
    "."         # amfCustom Dockerfile expects repo-root context (cert/, config/)
    "."         # smfCustom Dockerfile expects repo-root context (cert/, config/)
    "./e2sim"   # e2sim Dockerfile expects e2sim/ as build context
  )

  # Build all images in parallel and stop if one fails
  build_pids=()
  build_names=()
  for idx in "${!TAGS[@]}"; do
    tag="${TAGS[$idx]}"
    dockerfile="${DOCKERFILES[$idx]}"
    context="${CONTEXTS[$idx]}"
    docker build -t "$tag" -f "$dockerfile" "$context" &
    build_pids+=("$!")
    build_names+=("build $tag")
  done

  build_failed=0
  for idx in "${!build_pids[@]}"; do
    pid="${build_pids[$idx]}"
    name="${build_names[$idx]}"
    if wait "$pid"; then
      echo "[OK] $name"
    else
      echo "[ERROR] $name" >&2
      build_failed=1
    fi
  done

  if ((build_failed)); then
    echo "Build failed, aborting push." >&2
    exit 1
  fi

  # Push all images in parallel and stop if one fails
  push_pids=()
  push_names=()
  for tag in "${TAGS[@]}"; do
    docker push "$tag" &
    push_pids+=("$!")
    push_names+=("push $tag")
  done

  push_failed=0
  for idx in "${!push_pids[@]}"; do
    pid="${push_pids[$idx]}"
    name="${push_names[$idx]}"
    if wait "$pid"; then
      echo "[OK] $name"
    else
      echo "[ERROR] $name" >&2
      push_failed=1
    fi
  done

  if ((push_failed)); then
    echo "One or more pushes failed." >&2
    exit 1
  fi
fi

git add .
git commit -m "$COMMIT_MSG"
git push
