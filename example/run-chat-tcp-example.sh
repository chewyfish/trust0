#!/usr/bin/env bash

set -euo pipefail

EXAMPLE_DIR=$(dirname "$0")
NCAT_CMD=ncat
TMUX_CMD=tmux

# Perform runtime configuration

${EXAMPLE_DIR}/run-configure.sh

# Check pre-requisites

ERROR_MSG="$(make check-prereqs-example-chat-tcp)"

if [ -n "${ERROR_MSG}" ]; then
  echo "${ERROR_MSG}"
  exit 1
fi

# Build binaries

make gateway-server-pki
make client-pki
make trust0-gateway
make trust0-client

# Run example in tmux session

ARG1=${1:-}
if [ "$ARG1" == "verbose" ]; then
  GATEWAY_BIN_ARGS="--verbose --no-mask-addrs"
  CLIENT_BIN_ARGS="--verbose"
else
  GATEWAY_BIN_ARGS="--no-mask-addrs"
  CLIENT_BIN_ARGS=""
fi

source "${EXAMPLE_DIR}"/target/example.conf

PS1='$ ' ${TMUX_CMD} new-session -s trust0-chat-tcp-example \; \
  set -g mouse on \; \
  send-keys '(clear && read -p "Step 1: Hit <Enter> to run chat server (or prior to executing chat client)" && '"${NCAT_CMD}"' -v -k -l -p '"${CHAT_SERVICE__PORT}"' --chat)' C-m \; \
  split-window -v -l 83% \; \
  send-keys '(clear && read -p "Step 2: Hit <Enter> to run trust0 gateway" && make run-trust0-gateway-nodeps EXECBIN_EXTRA_ARGS="'"${GATEWAY_BIN_ARGS}"'")' C-m \; \
  split-window -v -l 67% \; \
  send-keys '(clear && echo "Step 3.1: Hit <Enter> to run trust0 client (after gateway is up)" && read -p "Step 3.2: Enter \"start -s chat-tcp -p '"${CHAT_PROXY__PORT}"'\" (to start service proxy)" && make run-trust0-client-nodeps EXECBIN_EXTRA_ARGS="'"${CLIENT_BIN_ARGS}"'")' C-m \; \
  split-window -v -l 50% \; \
  send-keys '(clear && read -p "Step 4: Hit <Enter> to run 1st chat client (after service proxy has started)" && '"${NCAT_CMD}"' -v localhost '"${CHAT_PROXY__PORT}"')' C-m \; \
  split-window -h -l 50% \; \
  send-keys '(clear && echo "Step 5.1: Hit <Enter> to run 2nd chat client (after service proxy has started)" && read -p "Step 5.2: Enter chat messages between chat clients" && '"${NCAT_CMD}"' -v localhost '"${CHAT_PROXY__PORT}"')' C-m \; \
  select-pane -t 0 \; \
  split-window -h -l 25% \; \
  send-keys '(clear && read -p "Step Last: Hit <Enter> to shutdown example" && ('"${TMUX_CMD}"' kill-session -t trust0-chat-tcp-example))' C-m \; \
  select-pane -t 0 \;

