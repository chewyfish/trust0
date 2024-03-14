SHELL:=bash

# Params

EXAMPLE_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
EXAMPLE_BUILD_DIR=${EXAMPLE_DIR}/target
EXAMPLE_CONFIG_FILE=${EXAMPLE_BUILD_DIR}/example.conf
PROJECT_DIR=${EXAMPLE_DIR}/..
PROJECT_RESOURCES_DIR=${PROJECT_DIR}/resources
PROJECT_BINARIES_BUILD_DIR=${PROJECT_DIR}/target/debug
UID=1000
GID=1000

CARGO_CMD=cargo
DOCKER_CMD=docker
DOCKER_COMPOSE_CMD=docker-compose

CA_ENABLED=false

PKI_PROVIDER_OPENSSL=openssl
PKI_PROVIDER_TRUST0=trust0
PKI_PROVIDER_DOCKER_TRUST0=docker-trust0
PKI_PROVIDER_DEFAULT=${PKI_PROVIDER_TRUST0}

ifeq ($(CA_ENABLED),false)
PKI_PROVIDER=${PKI_PROVIDER_DEFAULT}
else
PKI_PROVIDER=${PKI_PROVIDER_TRUST0}
endif

CARGOBUILD_GATEWAY_ARGS=
#CARGOBUILD_GATEWAY_ARGS=--features mysql_db
#CARGOBUILD_GATEWAY_ARGS=--features postgres_db
CARGOBUILD_EXTRA_ARGS=
EXECBIN_EXTRA_ARGS=
EXECBIN_EXTRA_CLIENT_ARGS=

include ${EXAMPLE_CONFIG_FILE}

# Params - Datasource

DATASOURCE_INMEMDB_DB_CONNECT=${EXAMPLE_BUILD_DIR}
DATASOURCE_MYSQLDB_DB_CONNECT=mysql://t0user:t0pass@localhost:3306/trust0
DATASOURCE_POSTGRESDB_DB_CONNECT=postgres://t0user:t0pass@localhost:5432/trust0

# Params - Certificate Authority

ROOT_CA__PKI_NAME=example-ca.local
ROOT_CA__PKI_VALID_NOT_AFTER=2100-01-01T00:00:00Z
ROOT_CA__PKI_SUBJ_COUNTRY=US
ROOT_CA__PKI_SUBJ_STATE=CA
ROOT_CA__PKI_SUBJ_CITY=Nowhere
ROOT_CA__PKI_SUBJ_COMPANY=ExampleCA
ROOT_CA__PKI_SUBJ_DEPT=IT
ROOT_CA__PKI_SUBJ_COMMONNAME=${ROOT_CA__PKI_NAME}
ROOT_CA__PKI_CERT_FILE=${EXAMPLE_BUILD_DIR}/${ROOT_CA__PKI_NAME}.crt.pem
ROOT_CA__PKI_KEY_FILE=${EXAMPLE_BUILD_DIR}/${ROOT_CA__PKI_NAME}.key.pem
ROOT_CA__PKI_CRL_CONF_FILE=${EXAMPLE_BUILD_DIR}/${ROOT_CA__PKI_NAME}.crl.conf
ROOT_CA__PKI_DATABASE_FILE=${EXAMPLE_BUILD_DIR}/ca-index.txt
ROOT_CA__PKI_CRLNUMBER_FILE=${EXAMPLE_BUILD_DIR}/ca-crlnumber.txt

# Params - Trust Gateway

TRUST0_GATEWAY__PKI_NAME=example-gateway.local
TRUST0_GATEWAY__PKI_VALID_NOT_AFTER=2100-01-01T00:00:00Z
TRUST0_GATEWAY__PKI_SERIAL_NUM=03e7
TRUST0_GATEWAY__PKI_SUBJ_COUNTRY=US
TRUST0_GATEWAY__PKI_SUBJ_STATE=CA
TRUST0_GATEWAY__PKI_SUBJ_CITY=Nowhere0
TRUST0_GATEWAY__PKI_SUBJ_COMPANY=Example0
TRUST0_GATEWAY__PKI_SUBJ_DEPT=IT0
TRUST0_GATEWAY__PKI_SUBJ_COMMONNAME=${TRUST0_GATEWAY__PKI_NAME}
TRUST0_GATEWAY__PKI_HOST_DNS1=example-gateway.local
TRUST0_GATEWAY__PKI_HOST_DNS2=localhost
TRUST0_GATEWAY__PKI_HOST_IP1=127.0.0.1
TRUST0_GATEWAY__PKI_HOST_IP2=127.1.0.3
TRUST0_GATEWAY__PKI_CERT_FILE=${EXAMPLE_BUILD_DIR}/${TRUST0_GATEWAY__PKI_NAME}.crt.pem
TRUST0_GATEWAY__PKI_KEY_FILE=${EXAMPLE_BUILD_DIR}/${TRUST0_GATEWAY__PKI_NAME}.key.pem
TRUST0_GATEWAY__BINARY_NAME=trust0-gateway
TRUST0_GATEWAY__BINARY_FILE=${PROJECT_BINARIES_BUILD_DIR}/${TRUST0_GATEWAY__BINARY_NAME}
TRUST0_GATEWAY__HOST=localhost
TRUST0_GATEWAY__BIND_HOST=[::1]
TRUST0_GATEWAY__SERVICE_HOST=${TRUST0_GATEWAY__HOST}
TRUST0_GATEWAY__CA_VALIDITY_PERIOD_DAYS=20
TRUST0_GATEWAY__CA_REISSUANCE_THRESHOLD_DAYS=15

TRUST0_GATEWAY__DATASOURCE=in-memory-db
TRUST0_GATEWAY__DB_CONNECT=${DATASOURCE_INMEMDB_DB_CONNECT}
#TRUST0_GATEWAY__DATASOURCE=mysql-db
#TRUST0_GATEWAY__DB_CONNECT=${DATASOURCE_MYSQLDB_DB_CONNECT}
#TRUST0_GATEWAY__DATASOURCE=postgres-db
#TRUST0_GATEWAY__DB_CONNECT=${DATASOURCE_POSTGRESDB_DB_CONNECT}

# Params - Trust Client

TRUST0_CLIENT__PKI_NAME=example-client.local
TRUST0_CLIENT__PKI_VALID_NOT_AFTER=2100-01-01T00:00:00Z
TRUST0_CLIENT__PKI_SERIAL_NUM=03e8
TRUST0_CLIENT__PKI_SUBJ_COUNTRY=US
TRUST0_CLIENT__PKI_SUBJ_STATE=CA
TRUST0_CLIENT__PKI_SUBJ_CITY=Nowhere1
TRUST0_CLIENT__PKI_SUBJ_COMPANY=Example1
TRUST0_CLIENT__PKI_SUBJ_DEPT=IT1
TRUST0_CLIENT__PKI_SUBJ_COMMONNAME=${TRUST0_CLIENT__PKI_NAME}
TRUST0_CLIENT__PKI_SUBJ_USERID=100
TRUST0_CLIENT__PKI_SUBJ_PLATFORM=Linux
TRUST0_CLIENT__PKI_EMAIL=support@example-client.local
TRUST0_CLIENT__PKI_CERT_FILE=${EXAMPLE_BUILD_DIR}/${TRUST0_CLIENT__PKI_NAME}.crt.pem
TRUST0_CLIENT__PKI_KEY_FILE=${EXAMPLE_BUILD_DIR}/${TRUST0_CLIENT__PKI_NAME}.key.pem
TRUST0_CLIENT__BINARY_NAME=trust0-client
TRUST0_CLIENT__BINARY_FILE=${PROJECT_BINARIES_BUILD_DIR}/${TRUST0_CLIENT__BINARY_NAME}
TRUST0_CLIENT__BIND_HOST=127.0.0.1

# Params - Docker-related

TRUST0_CLIENT__DOCKER_CMD=${DOCKER_CMD} run --name trust0-client-example -u ${UID}:${GID} -it --rm --network host -v ${EXAMPLE_BUILD_DIR}:${EXAMPLE_BUILD_DIR} trust0-client:latest
TRUST0_GATEWAY__DOCKER_CMD=${DOCKER_CMD} run --name trust0-gateway-example -u ${UID}:${GID} -it --rm --network host -v ${EXAMPLE_BUILD_DIR}:${EXAMPLE_BUILD_DIR} trust0-gateway:latest

# Params - CRL

CRLSUPPORT__PKI_GATEWAY_CONFIGURED_FILE=${EXAMPLE_BUILD_DIR}/revoked.crl.pem
CRLSUPPORT__PKI_REVOKE_CLIENT_FILE=${EXAMPLE_BUILD_DIR}/revoked-${TRUST0_CLIENT__PKI_NAME}.crl.pem

# Targets

.PHONY: default clean-all trust0-common trust0-tools-image root-ca-pki generate-root-ca-pki-resources gateway-server-pki generate-gateway-pki-resources client-pki generate-client-pki-resources trust0-gateway trust0-gateway-image trust0-client trust0-client-image run-trust0-gateway run-trust0-client run-trust0-gateway-nodeps run-trust0-gateway-image-nodeps run-trust0-client-nodeps run-trust0-client-image-nodeps setup-crl-files

default:

clean-all:
	@rm -f ${EXAMPLE_BUILD_DIR}/*.srl
	@rm -f ${EXAMPLE_BUILD_DIR}/*.pem
	@rm -f ${EXAMPLE_BUILD_DIR}/*.pem.conf
	@rm -f ${EXAMPLE_BUILD_DIR}/*.pem.csr.conf
	@rm -f ${EXAMPLE_BUILD_DIR}/*.pem.csr-
	@rm -f ${ROOT_CA__PKI_CRL_CONF_FILE}
	@rm -f ${ROOT_CA__PKI_DATABASE_FILE}
	@rm -f ${ROOT_CA__PKI_DATABASE_FILE}.*
	@rm -f ${ROOT_CA__PKI_CRLNUMBER_FILE}
	@rm -f ${ROOT_CA__PKI_CRLNUMBER_FILE}.*
	@rm -f ${CRLSUPPORT__PKI_GATEWAY_CONFIGURED_FILE}
	@rm -f ${CRLSUPPORT__PKI_REVOKE_CLIENT_FILE}

${EXAMPLE_CONFIG_FILE}:
	@(test -f "$@" || (echo "Example configuration file '$@' unavailable. Please run '${EXAMPLE_DIR}/run-configure.sh'" && exit 1))

trust0-common:
	${CARGO_CMD} build --color=always --manifest-path ${PROJECT_DIR}/crates/common/Cargo.toml

# Targets - PKI Provider

ifeq ($(PKI_PROVIDER),$(PKI_PROVIDER_OPENSSL))
  include ${EXAMPLE_DIR}/pki-provider-openssl.mk
else ifeq ($(PKI_PROVIDER),$(PKI_PROVIDER_DOCKER_TRUST0))
  include ${EXAMPLE_DIR}/pki-provider-docker-trust0.mk
else
  include ${EXAMPLE_DIR}/pki-provider-trust0.mk
endif

# Targets - Tools

trust0-tools-image:
	${DOCKER_COMPOSE_CMD} -f ${PROJECT_RESOURCES_DIR}/docker/docker-compose-build.yml build trust0-tools

# Targets - ROOT CA

root-ca-pki: generate-root-ca-pki-resources

# Targets - Trust Gateway

gateway-server-pki: generate-gateway-pki-resources

trust0-gateway: trust0-common
	${CARGO_CMD} build --color=always --bin trust0-gateway --manifest-path ${PROJECT_DIR}/crates/gateway/Cargo.toml ${CARGOBUILD_GATEWAY_ARGS} ${CARGOBUILD_EXTRA_ARGS}

trust0-gateway-image:
	${DOCKER_COMPOSE_CMD} -f ${PROJECT_RESOURCES_DIR}/docker/docker-compose-build.yml build trust0-gateway

ifeq ($(CA_ENABLED),false)
run-trust0-gateway: trust0-gateway
	${TRUST0_GATEWAY__BINARY_FILE} --host ${TRUST0_GATEWAY__BIND_HOST} --port ${TRUST0_GATEWAY__PORT} --cert-file ${TRUST0_GATEWAY__PKI_CERT_FILE} --key-file ${TRUST0_GATEWAY__PKI_KEY_FILE} --auth-cert-file ${ROOT_CA__PKI_CERT_FILE} --gateway-service-host ${TRUST0_GATEWAY__SERVICE_HOST} ${EXECBIN_EXTRA_ARGS} --datasource ${TRUST0_GATEWAY__DATASOURCE} --db-connect ${TRUST0_GATEWAY__DB_CONNECT}

run-trust0-gateway-nodeps:
	${TRUST0_GATEWAY__BINARY_FILE} --host ${TRUST0_GATEWAY__BIND_HOST} --port ${TRUST0_GATEWAY__PORT} --cert-file ${TRUST0_GATEWAY__PKI_CERT_FILE} --key-file ${TRUST0_GATEWAY__PKI_KEY_FILE} --auth-cert-file ${ROOT_CA__PKI_CERT_FILE} --gateway-service-host ${TRUST0_GATEWAY__SERVICE_HOST} ${EXECBIN_EXTRA_ARGS} --datasource ${TRUST0_GATEWAY__DATASOURCE} --db-connect ${TRUST0_GATEWAY__DB_CONNECT}

run-trust0-gateway-image-nodeps:
	${TRUST0_GATEWAY__DOCKER_CMD} --host ${TRUST0_GATEWAY__BIND_HOST} --port ${TRUST0_GATEWAY__PORT} --cert-file ${TRUST0_GATEWAY__PKI_CERT_FILE} --key-file ${TRUST0_GATEWAY__PKI_KEY_FILE} --auth-cert-file ${ROOT_CA__PKI_CERT_FILE} --gateway-service-host ${TRUST0_GATEWAY__SERVICE_HOST} ${EXECBIN_EXTRA_ARGS} --datasource ${TRUST0_GATEWAY__DATASOURCE} --db-connect ${TRUST0_GATEWAY__DB_CONNECT}
else
run-trust0-gateway: trust0-gateway
	${TRUST0_GATEWAY__BINARY_FILE} --host ${TRUST0_GATEWAY__BIND_HOST} --port ${TRUST0_GATEWAY__PORT} --cert-file ${TRUST0_GATEWAY__PKI_CERT_FILE} --key-file ${TRUST0_GATEWAY__PKI_KEY_FILE} --auth-cert-file ${ROOT_CA__PKI_CERT_FILE} --auth-key-file ${ROOT_CA__PKI_KEY_FILE} --gateway-service-host ${TRUST0_GATEWAY__SERVICE_HOST} ${EXECBIN_EXTRA_ARGS} --datasource ${TRUST0_GATEWAY__DATASOURCE} --db-connect ${TRUST0_GATEWAY__DB_CONNECT} --mfa-scheme scram-sha256 --ca-enabled --ca-key-algorithm ${TRUST0_KEYALG_TYPE} --ca-validity-period-days ${TRUST0_GATEWAY__CA_VALIDITY_PERIOD_DAYS} --ca-reissuance-threshold-days ${TRUST0_GATEWAY__CA_REISSUANCE_THRESHOLD_DAYS}

run-trust0-gateway-nodeps:
	${TRUST0_GATEWAY__BINARY_FILE} --host ${TRUST0_GATEWAY__BIND_HOST} --port ${TRUST0_GATEWAY__PORT} --cert-file ${TRUST0_GATEWAY__PKI_CERT_FILE} --key-file ${TRUST0_GATEWAY__PKI_KEY_FILE} --auth-cert-file ${ROOT_CA__PKI_CERT_FILE} --auth-key-file ${ROOT_CA__PKI_KEY_FILE} --gateway-service-host ${TRUST0_GATEWAY__SERVICE_HOST} ${EXECBIN_EXTRA_ARGS} --datasource ${TRUST0_GATEWAY__DATASOURCE} --db-connect ${TRUST0_GATEWAY__DB_CONNECT} --mfa-scheme scram-sha256 --ca-enabled --ca-key-algorithm ${TRUST0_KEYALG_TYPE} --ca-validity-period-days ${TRUST0_GATEWAY__CA_VALIDITY_PERIOD_DAYS} --ca-reissuance-threshold-days ${TRUST0_GATEWAY__CA_REISSUANCE_THRESHOLD_DAYS}

run-trust0-gateway-image-nodeps:
	${TRUST0_GATEWAY__DOCKER_CMD} --host ${TRUST0_GATEWAY__BIND_HOST} --port ${TRUST0_GATEWAY__PORT} --cert-file ${TRUST0_GATEWAY__PKI_CERT_FILE} --key-file ${TRUST0_GATEWAY__PKI_KEY_FILE} --auth-cert-file ${ROOT_CA__PKI_CERT_FILE} --auth-key-file ${ROOT_CA__PKI_KEY_FILE} --gateway-service-host ${TRUST0_GATEWAY__SERVICE_HOST} ${EXECBIN_EXTRA_ARGS} --datasource ${TRUST0_GATEWAY__DATASOURCE} --db-connect ${TRUST0_GATEWAY__DB_CONNECT} --mfa-scheme scram-sha256 --ca-enabled --ca-key-algorithm ${TRUST0_KEYALG_TYPE} --ca-validity-period-days ${TRUST0_GATEWAY__CA_VALIDITY_PERIOD_DAYS} --ca-reissuance-threshold-days ${TRUST0_GATEWAY__CA_REISSUANCE_THRESHOLD_DAYS}
endif

# Targets - Trust Client

client-pki: generate-client-pki-resources

trust0-client: trust0-common
	${CARGO_CMD} build --color=always --bin trust0-client --manifest-path ${PROJECT_DIR}/crates/client/Cargo.toml ${CARGOBUILD_EXTRA_ARGS}

trust0-client-image:
	${DOCKER_COMPOSE_CMD} -f ${PROJECT_RESOURCES_DIR}/docker/docker-compose-build.yml build trust0-client

run-trust0-client: trust0-client
	${TRUST0_CLIENT__BINARY_FILE} --host ${TRUST0_CLIENT__BIND_HOST} --gateway-host ${TRUST0_GATEWAY__HOST} --gateway-port ${TRUST0_GATEWAY__PORT} --auth-key-file ${TRUST0_CLIENT__PKI_KEY_FILE} --auth-cert-file ${TRUST0_CLIENT__PKI_CERT_FILE} --ca-root-cert-file ${ROOT_CA__PKI_CERT_FILE} ${EXECBIN_EXTRA_ARGS}

run-trust0-client-nodeps:
	${TRUST0_CLIENT__BINARY_FILE} --host ${TRUST0_CLIENT__BIND_HOST} --gateway-host ${TRUST0_GATEWAY__HOST} --gateway-port ${TRUST0_GATEWAY__PORT} --auth-key-file ${TRUST0_CLIENT__PKI_KEY_FILE} --auth-cert-file ${TRUST0_CLIENT__PKI_CERT_FILE} --ca-root-cert-file ${ROOT_CA__PKI_CERT_FILE} ${EXECBIN_EXTRA_ARGS}

run-trust0-client-image-nodeps:
	${TRUST0_CLIENT__DOCKER_CMD} --host ${TRUST0_CLIENT__BIND_HOST} --gateway-host ${TRUST0_GATEWAY__HOST} --gateway-port ${TRUST0_GATEWAY__PORT} --auth-key-file ${TRUST0_CLIENT__PKI_KEY_FILE} --auth-cert-file ${TRUST0_CLIENT__PKI_CERT_FILE} --ca-root-cert-file ${ROOT_CA__PKI_CERT_FILE} ${EXECBIN_EXTRA_ARGS}
