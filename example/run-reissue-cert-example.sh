#!/usr/bin/env bash

set -euo pipefail

EXAMPLE_DIR=$(dirname "$0")

# Build binaries/pki/config/db/...

source "${EXAMPLE_DIR}"/run-configure.sh

XDG_CACHE_HOME="${EXAMPLE_BUILD_DIR}"/xdg/cache
XDG_CONFIG_HOME="${EXAMPLE_BUILD_DIR}"/xdg/config
XDG_DATA_HOME="${EXAMPLE_BUILD_DIR}"/xdg/data
mkdir -p "${XDG_CACHE_HOME}" "${XDG_CONFIG_HOME}" "${XDG_DATA_HOME}"
export XDG_CACHE_HOME XDG_CONFIG_HOME XDG_DATA_HOME

next_week=$(date -u --date '7 day' +"%FT%TZ")

GMAKE_CMD="${GMAKE_CMD} CA_ENABLED=true TRUST0_CLIENT__PKI_CERT_FILE=${XDG_DATA_HOME}/Trust0/pki/trust0-client.cert.pem TRUST0_CLIENT__PKI_KEY_FILE=${XDG_DATA_HOME}/Trust0/pki/trust0-client.key.pem TRUST0_CLIENT__PKI_VALID_NOT_AFTER=${next_week}"

${GMAKE_CMD} clean-all
${GMAKE_CMD} trust0-gateway
${GMAKE_CMD} trust0-client
${GMAKE_CMD} root-ca-pki
${GMAKE_CMD} gateway-server-pki
${GMAKE_CMD} client-pki

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

PS1='$ ' "${TMUX_CMD}" new-session -s trust0-chat-tcp-example \; \
  set -g mouse on \; \
  send-keys '(clear && read -p "Step 1: Hit <Enter> to run chat server (or prior to executing chat client)" && "'"${NCAT_CMD}"'" -v -k -l -p '"${CHAT_SERVICE__PORT}"' --chat)' C-m \; \
  split-window -v -l 83% \; \
  send-keys '(clear && read -p "Step 2: Hit <Enter> to run trust0 gateway" && '"${GMAKE_CMD}"' run-trust0-gateway-nodeps EXECBIN_EXTRA_ARGS="'"${GATEWAY_BIN_ARGS}"'")' C-m \; \
  split-window -v -l 67% \; \
  send-keys '(clear && echo "Step 3.1: Hit <Enter> to run trust0 client (after gateway is up)" && echo "Step 3.2: \"login\" then \"quit\" after message is shown about new cert/key files created" && echo "Step 3.3: Hit <Up-Arrow> then <Enter> to re-execute command to start trust0 client" && read -p "Step 3.4: Enter \"start -s chat-tcp -p '"${CHAT_PROXY__PORT}"'\" (to start service proxy)" && '"${GMAKE_CMD}"' run-trust0-client-nodeps EXECBIN_EXTRA_ARGS="'"${CLIENT_BIN_ARGS}"'")' C-m \; \
  split-window -v -l 50% \; \
  send-keys '(clear && read -p "Step 4: Hit <Enter> to run 1st chat client (after service proxy has started)" && "'"${NCAT_CMD}"'" -v 127.0.0.1 '"${CHAT_PROXY__PORT}"')' C-m \; \
  split-window -h -l 50% \; \
  send-keys '(clear && echo "Step 5.1: Hit <Enter> to run 2nd chat client (after service proxy has started)" && read -p "Step 5.2: Enter chat messages between chat clients" && "'"${NCAT_CMD}"'" -v 127.0.0.1 '"${CHAT_PROXY__PORT}"')' C-m \; \
  select-pane -t 0 \; \
  split-window -h -l 25% \; \
  send-keys '(clear && read -p "Step Last: Hit <Enter> to shutdown example" && ("'"${TMUX_CMD}"'" kill-session -t trust0-chat-tcp-example))' C-m \; \
  select-pane -t 0 \;

