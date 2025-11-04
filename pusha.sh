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
  docker build -t zhria/n3iwfcustom:latest -f ./n3iwfCustom/Dockerfile .
  docker build -t zhria/amfcustom:latest -f ./amfCustom/Dockerfile .
  docker build -t zhria/smfcustom:latest -f ./smfCustom/Dockerfile .
  docker push zhria/n3iwfcustom:latest
  docker push zhria/amfcustom:latest
  docker push zhria/smfcustom:latest
fi

git add .
git commit -m "$COMMIT_MSG"
git push