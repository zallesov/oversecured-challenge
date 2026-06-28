#!/usr/bin/env bash
# Build the SAST server images, ship them to a remote host without a registry (docker save ->
# scp -> docker load), sync the compose file + supporting dirs, and bring the stack up under the
# isolated `oversecured` compose project. Idempotent; only ever touches the `oversecured` project.
set -euo pipefail

SSH_HOST="${SSH_HOST:-hermes}"
REMOTE_DIR="${REMOTE_DIR:-oversecured-stack}"   # relative to remote $HOME
PROJECT="oversecured"
COMPOSE_FILE="docker-compose.server.yml"
IMAGE_TAG="${IMAGE_TAG:-latest}"
IMAGES=("oversecured-ui:${IMAGE_TAG}" "oversecured-worker:${IMAGE_TAG}")

cd "$(dirname "$0")/.."   # repo root

if [[ ! -f .env.server ]]; then
  echo "ERROR: .env.server not found. cp .env.server.example .env.server and set JWT_SECRET." >&2
  exit 1
fi

echo "==> [1/6] Build images locally for the remote's arch (linux/amd64)"
# Remote (hermes) is x86_64; a Mac builds arm64 by default. Force amd64 (QEMU-emulated on arm).
export DOCKER_DEFAULT_PLATFORM="${TARGET_PLATFORM:-linux/amd64}"
docker compose -f "$COMPOSE_FILE" -p "$PROJECT" --env-file .env.server build

echo "==> [2/6] Save images to compressed tarballs"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
docker save "${IMAGES[@]}" | gzip > "$TMP/images.tar.gz"
echo "    $(du -h "$TMP/images.tar.gz" | cut -f1) images.tar.gz"

echo "==> [3/6] Ensure remote dir and sync project files"
ssh "$SSH_HOST" "mkdir -p ${REMOTE_DIR}"
# Compose file, env, and the dirs the worker bind-mounts read-only.
rsync -az --delete "$COMPOSE_FILE" .env.server "$SSH_HOST:${REMOTE_DIR}/"
rsync -az --delete rules "$SSH_HOST:${REMOTE_DIR}/"
rsync -az --delete test-subjects "$SSH_HOST:${REMOTE_DIR}/"

echo "==> [4/6] Copy image bundle to remote"
scp -q "$TMP/images.tar.gz" "$SSH_HOST:${REMOTE_DIR}/images.tar.gz"

echo "==> [5/6] Load images on remote"
ssh "$SSH_HOST" "gunzip -c ${REMOTE_DIR}/images.tar.gz | docker load && rm -f ${REMOTE_DIR}/images.tar.gz"

echo "==> [6/6] Bring stack up on remote (project: ${PROJECT})"
ssh "$SSH_HOST" "cd ${REMOTE_DIR} && docker compose -f ${COMPOSE_FILE} -p ${PROJECT} --env-file .env.server up -d"

echo
echo "Done. Remote published ports: UI :18030, Temporal UI :18080 (loopback unless proxied)."
ssh "$SSH_HOST" "cd ${REMOTE_DIR} && docker compose -f ${COMPOSE_FILE} -p ${PROJECT} --env-file .env.server ps"
