#!/usr/bin/env bash

set -euo pipefail

EXAMPLE_DIR=$(dirname "$0")
EXAMPLE_BUILD_DIR="${EXAMPLE_DIR}/target"
EXAMPLE_CONFIG_FILE="${EXAMPLE_BUILD_DIR}/example.conf"

DATASOURCE_INMEMDB_ACCESS_M4_FILE="${EXAMPLE_DIR}/example-db-access.json.m4"
DATASOURCE_INMEMDB_ACCESS_FILE="${EXAMPLE_BUILD_DIR}/example-db-access.json"
DATASOURCE_INMEMDB_SERVICE_M4_FILE="${EXAMPLE_DIR}/example-db-service.json.m4"
DATASOURCE_INMEMDB_SERVICE_FILE="${EXAMPLE_BUILD_DIR}/example-db-service.json"
DATASOURCE_INMEMDB_ROLE_M4_FILE="${EXAMPLE_DIR}/example-db-role.json.m4"
DATASOURCE_INMEMDB_ROLE_FILE="${EXAMPLE_BUILD_DIR}/example-db-role.json"
DATASOURCE_INMEMDB_USER_M4_FILE="${EXAMPLE_DIR}/example-db-user.json.m4"
DATASOURCE_INMEMDB_USER_FILE="${EXAMPLE_BUILD_DIR}/example-db-user.json"

GMAKE_CMD="gmake"
CARGO_CMD="cargo"
OPENSSL_CMD="openssl"
M4_CMD="m4"
TMUX_CMD="tmux"
NCAT_CMD="ncat"

# Check pre-requisites

PREREQ_MISSING=0

if ((BASH_VERSINFO[0] < 4)); then
  echo "Bash version 4 or higher required"
  PREREQ_MISSING=1
fi

function check_command_exists() {
  local command="$1"
  if ! which "${command}" 2> /dev/null > /dev/null; then
    echo "Command '${command}' missing, please install"
    PREREQ_MISSING=1
  fi
}

check_command_exists "${GMAKE_CMD}"
check_command_exists "${CARGO_CMD}"
check_command_exists "${OPENSSL_CMD}"
check_command_exists "${M4_CMD}"
check_command_exists "${TMUX_CMD}"
check_command_exists "${NCAT_CMD}"

if [ "${PREREQ_MISSING}" == "1" ]; then
  exit 1
fi

# Check if configuration is needed

RECONFIGURE=n
if [ -f "${EXAMPLE_CONFIG_FILE}" ]; then
  read -p "Example config file already exists, enter 'y' to reconfigure this file: " reconf_config
  if [ "$reconf_config" == 'y' ]; then
    RECONFIGURE=y
  fi
else
  RECONFIGURE=y
fi

read -p "If example requires secondary authentication credentials, please use \"user1\", \"pass1\""

# Create core application configuration files

if [ "$RECONFIGURE" == 'y' ]; then
  mkdir -p "${EXAMPLE_BUILD_DIR}"
  rm -f "${EXAMPLE_CONFIG_FILE}" "${DATASOURCE_INMEMDB_ACCESS_FILE}" "${DATASOURCE_INMEMDB_SERVICE_FILE}" "${DATASOURCE_INMEMDB_ROLE_FILE}" "${DATASOURCE_INMEMDB_USER_FILE}"
  read -rp "Enter an available port for the trust0 gateway: " gateway_port && echo TRUST0_GATEWAY__PORT=${gateway_port} >> ${EXAMPLE_CONFIG_FILE}
  read -rp "Enter an available port for the chat service: " chat_service_port && echo CHAT_SERVICE__PORT=${chat_service_port} >> ${EXAMPLE_CONFIG_FILE}
  read -rp "Enter an available port for the chat proxy: " chat_proxy_port && echo CHAT_PROXY__PORT=${chat_proxy_port} >> ${EXAMPLE_CONFIG_FILE}
  read -rp "Enter an available port for the echo service: " echo_service_port && echo ECHO_SERVICE__PORT=${echo_service_port} >> ${EXAMPLE_CONFIG_FILE}
  read -rp "Enter an available port for the echo proxy: " echo_proxy_port && echo ECHO_PROXY__PORT=${echo_proxy_port} >> ${EXAMPLE_CONFIG_FILE}
fi

if [ ! -f "${DATASOURCE_INMEMDB_ACCESS_FILE}" ] ||  [ ! -f "${DATASOURCE_INMEMDB_SERVICE_FILE}" ] ||  [ ! -f "${DATASOURCE_INMEMDB_ROLE_FILE}" ] ||  [ ! -f "${DATASOURCE_INMEMDB_USER_FILE}" ]; then
  source "${EXAMPLE_CONFIG_FILE}"
  ${M4_CMD} "${DATASOURCE_INMEMDB_ACCESS_M4_FILE}" > "${DATASOURCE_INMEMDB_ACCESS_FILE}"
  ${M4_CMD} -D xCHAT_PORT="${CHAT_SERVICE__PORT}" -D xECHO_PORT="${ECHO_SERVICE__PORT}" "${DATASOURCE_INMEMDB_SERVICE_M4_FILE}" > "${DATASOURCE_INMEMDB_SERVICE_FILE}"
  ${M4_CMD} "${DATASOURCE_INMEMDB_ROLE_M4_FILE}" > "${DATASOURCE_INMEMDB_ROLE_FILE}"
  ${M4_CMD} "${DATASOURCE_INMEMDB_USER_M4_FILE}" > "${DATASOURCE_INMEMDB_USER_FILE}"
fi
