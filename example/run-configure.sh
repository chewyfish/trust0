#!/usr/bin/env bash

set -euo pipefail

EXAMPLE_DIR=$(dirname "$0")
EXAMPLE_BUILD_DIR="${EXAMPLE_DIR}/target"
EXAMPLE_CONFIG_FILE="${EXAMPLE_BUILD_DIR}/example.conf"
DATASOURCE_INMEMDB_ACCESS_M4_FILE="${EXAMPLE_DIR}/example-db-access.json.m4"
DATASOURCE_INMEMDB_ACCESS_FILE="${EXAMPLE_BUILD_DIR}/example-db-access.json"
DATASOURCE_INMEMDB_SERVICE_M4_FILE="${EXAMPLE_DIR}/example-db-service.json.m4"
DATASOURCE_INMEMDB_SERVICE_FILE="${EXAMPLE_BUILD_DIR}/example-db-service.json"
DATASOURCE_INMEMDB_USER_M4_FILE="${EXAMPLE_DIR}/example-db-user.json.m4"
DATASOURCE_INMEMDB_USER_FILE="${EXAMPLE_BUILD_DIR}/example-db-user.json"
M4_CMD=m4

RECONFIGURE=n
if [ -f "${EXAMPLE_CONFIG_FILE}" ]; then
  read -p "Example config file already exists, enter 'y' to reconfigure this file: " reconf_config
  if [ "$reconf_config" == 'y' ]; then
    RECONFIGURE=y
  fi
else
  RECONFIGURE=y
fi

if [ "$RECONFIGURE" == 'y' ]; then
  mkdir -p "${EXAMPLE_BUILD_DIR}"
  rm -f "${EXAMPLE_CONFIG_FILE}" "${DATASOURCE_INMEMDB_ACCESS_FILE}" "${DATASOURCE_INMEMDB_SERVICE_FILE}" "${DATASOURCE_INMEMDB_USER_FILE}"
  read -rp "Enter an available port for the trust0 gateway: " gateway_port && echo TRUST0_GATEWAY__PORT=${gateway_port} >> ${EXAMPLE_CONFIG_FILE}
  read -rp "Enter an available port for the chat service: " chat_service_port && echo CHAT_SERVICE__PORT=${chat_service_port} >> ${EXAMPLE_CONFIG_FILE}
  read -rp "Enter an available port for the chat proxy: " chat_proxy_port && echo CHAT_PROXY__PORT=${chat_proxy_port} >> ${EXAMPLE_CONFIG_FILE}
  read -rp "Enter an available port for the echo service: " echo_service_port && echo ECHO_SERVICE__PORT=${echo_service_port} >> ${EXAMPLE_CONFIG_FILE}
  read -rp "Enter an available port for the echo proxy: " echo_proxy_port && echo ECHO_PROXY__PORT=${echo_proxy_port} >> ${EXAMPLE_CONFIG_FILE}
fi

if [ ! -f "${DATASOURCE_INMEMDB_SERVICE_FILE}" ]; then
  source "${EXAMPLE_CONFIG_FILE}"
  ${M4_CMD} "${DATASOURCE_INMEMDB_ACCESS_M4_FILE}" > "${DATASOURCE_INMEMDB_ACCESS_FILE}"
  ${M4_CMD} -D xCHAT_PORT="${CHAT_SERVICE__PORT}" -D xECHO_PORT="${ECHO_SERVICE__PORT}" "${DATASOURCE_INMEMDB_SERVICE_M4_FILE}" > "${DATASOURCE_INMEMDB_SERVICE_FILE}"
  ${M4_CMD} "${DATASOURCE_INMEMDB_USER_M4_FILE}" > "${DATASOURCE_INMEMDB_USER_FILE}"
fi
