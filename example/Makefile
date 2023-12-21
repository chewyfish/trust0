SHELL:=/bin/bash

# Params

EXAMPLE_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
EXAMPLE_BUILD_DIR=${EXAMPLE_DIR}/target
EXAMPLE_CONFIG_FILE=${EXAMPLE_BUILD_DIR}/example.conf
PROJECT_DIR=${EXAMPLE_DIR}/..
PROJECT_RESOURCES_DIR=${PROJECT_DIR}/resources

CARGO_CMD=cargo
OPENSSL_CMD=openssl
M4_CMD=m4
TMUX_CMD=tmux
NCAT_CMD=ncat
TRUST0_ADMIN_CMD=${PROJECT_RESOURCES_DIR}/trust0-admin.sh

CARGOBUILD_EXTRA_ARGS=
EXECBIN_EXTRA_ARGS=

include ${EXAMPLE_CONFIG_FILE}

# Params - Certificate Authority

ROOT_CA__PKI_NAME=example-ca.local
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
TRUST0_GATEWAY__BINARY_FILE=${PROJECT_DIR}/target/debug/${TRUST0_GATEWAY__BINARY_NAME}
TRUST0_GATEWAY__HOST=localhost
TRUST0_GATEWAY__SERVICE_HOST=${TRUST0_GATEWAY__HOST}

# Params - Trust Client

TRUST0_CLIENT__PKI_NAME=example-client.local
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
TRUST0_CLIENT__BINARY_FILE=${PROJECT_DIR}/target/debug/${TRUST0_CLIENT__BINARY_NAME}

# Params - Datasource

DATASOURCE_INMEMDB_ACCESS_FILE=${EXAMPLE_BUILD_DIR}/example-db-access.json
DATASOURCE_INMEMDB_SERVICE_FILE=${EXAMPLE_BUILD_DIR}/example-db-service.json
DATASOURCE_INMEMDB_USER_FILE=${EXAMPLE_BUILD_DIR}/example-db-user.json

# Params - CRL

CRLSUPPORT__PKI_GATEWAY_CONFIGURED_FILE=${EXAMPLE_BUILD_DIR}/revoked.crl.pem
CRLSUPPORT__PKI_REVOKE_CLIENT_FILE=${EXAMPLE_BUILD_DIR}/revoked-${TRUST0_CLIENT__PKI_NAME}.crl.pem

# Params - Key Algorithm

KEYALG_RSA_TYPE=rsa
KEYALG_RSA_PARAMS=4096
KEYALG_EC_TYPE=ec
KEYALG_EC_PARAMS=${EXAMPLE_BUILD_DIR}/ecparams.pem
#KEYALG_EC_CURVE=secp384r1
KEYALG_EC_CURVE=prime256v1
KEYALG_ED_TYPE=ed
KEYALG_ED_PARAMS=ed25519

# Update these 2 values to switch key algorithm type and params
KEYALG_TYPE=${KEYALG_RSA_TYPE}
KEYALG_PARAMS=${KEYALG_RSA_PARAMS}

# Targets

.PHONY: default clean-all root-ca-pki generate-root-ca-pki-resources gateway-server-pki generate-gateway-pki-resources client-pki generate-client-pki-resources trust0-gateway trust0-client run-trust0-gateway run-trust0-client run-trust0-gateway-nodeps run-trust0-client-nodeps setup-crl-files check-prereqs-examples check-prereqs-example-chat-tcp check-prereqs-example-echo-udp check-prereqs-example-revoke-cert

default:

clean-all:
	@rm -f ${EXAMPLE_BUILD_DIR}/*.srl
	@rm -f ${EXAMPLE_BUILD_DIR}/*.pem
	@rm -f ${EXAMPLE_BUILD_DIR}/*.pem.conf
	@rm -f ${EXAMPLE_BUILD_DIR}/*.pem.csr.conf
	@rm -f ${EXAMPLE_BUILD_DIR}/*.pem.csr
	@rm -f ${ROOT_CA__PKI_CRL_CONF_FILE}
	@rm -f ${ROOT_CA__PKI_DATABASE_FILE}
	@rm -f ${ROOT_CA__PKI_DATABASE_FILE}.*
	@rm -f ${ROOT_CA__PKI_CRLNUMBER_FILE}
	@rm -f ${ROOT_CA__PKI_CRLNUMBER_FILE}.*
	@rm -f ${DATASOURCE_INMEMDB_ACCESS_FILE}
	@rm -f ${DATASOURCE_INMEMDB_SERVICE_FILE}
	@rm -f ${DATASOURCE_INMEMDB_USER_FILE}
	@rm -f ${CRLSUPPORT__PKI_GATEWAY_CONFIGURED_FILE}
	@rm -f ${CRLSUPPORT__PKI_REVOKE_CLIENT_FILE}

${EXAMPLE_CONFIG_FILE}:
	@${EXAMPLE_DIR}/run_configure.sh

check-prereqs-examples:
	@(which ${CARGO_CMD} 2> /dev/null > /dev/null || echo "Command '${CARGO_CMD}' missing, please install")
	@(which ${OPENSSL_CMD} 2> /dev/null > /dev/null || echo "Command '${OPENSSL_CMD}' missing, please install")
	@(which ${M4_CMD} 2> /dev/null > /dev/null || echo "Command '${M4_CMD}' missing, please install")
	@(which ${TMUX_CMD} 2> /dev/null > /dev/null || echo "Command '${TMUX_CMD}' missing, please install")

check-prereqs-example-chat-tcp: check-prereqs-examples
check-prereqs-example-echo-udp: check-prereqs-examples
check-prereqs-example-revoke-cert: check-prereqs-examples

# Targets - ROOT CA

generate-root-ca-pki-resources: ${EXAMPLE_CONFIG_FILE}
	@echo "Creating root CA PKI resources"
	@([ '${KEYALG_TYPE}' != '${KEYALG_EC_TYPE}' ] || [ -f ${KEYALG_PARAMS} ] || ${OPENSSL_CMD} ecparam -name ${KEYALG_EC_CURVE} -out ${KEYALG_PARAMS})
	cd ${EXAMPLE_BUILD_DIR} && ${TRUST0_ADMIN_CMD} rootca-pki-creator --rootca-cert-filepath ${ROOT_CA__PKI_CERT_FILE} --rootca-key-filepath ${ROOT_CA__PKI_KEY_FILE} --key-algorithm ${KEYALG_TYPE}:${KEYALG_PARAMS} --subj-common-name ${ROOT_CA__PKI_SUBJ_COMMONNAME} --subj-country ${ROOT_CA__PKI_SUBJ_COUNTRY} --subj-state ${ROOT_CA__PKI_SUBJ_STATE} --subj-city ${ROOT_CA__PKI_SUBJ_CITY} --subj-company ${ROOT_CA__PKI_SUBJ_COMPANY} --subj-dept ${ROOT_CA__PKI_SUBJ_DEPT}
	@echo ""

.ONESHELL:
${ROOT_CA__PKI_CRL_CONF_FILE}: ${EXAMPLE_CONFIG_FILE}
	@echo "Creating $@"
	@cat <<- EOF > $@
		[ ca ]
		default_ca = ca_default
		[ ca_default ]
		database = ${ROOT_CA__PKI_DATABASE_FILE}
		crlnumber = ${ROOT_CA__PKI_CRLNUMBER_FILE}
		default_md = default
		crl_extensions = crl_ext
		[ crl_ext ]
		authorityKeyIdentifier = keyid,issuer
		EOF
	@echo ""

root-ca-pki: generate-root-ca-pki-resources ${ROOT_CA__PKI_CRL_CONF_FILE}

# Targets - Trust Gateway

generate-gateway-pki-resources: ${EXAMPLE_CONFIG_FILE}
	@echo "Creating gateway PKI resources"
	@([ '${KEYALG_TYPE}' != '${KEYALG_EC_TYPE}' ] || [ -f ${KEYALG_PARAMS} ] || ${OPENSSL_CMD} ecparam -name ${KEYALG_EC_CURVE} -out ${KEYALG_PARAMS})
	cd ${EXAMPLE_BUILD_DIR} && ${TRUST0_ADMIN_CMD} gateway-pki-creator --gateway-cert-filepath ${TRUST0_GATEWAY__PKI_CERT_FILE} --gateway-key-filepath ${TRUST0_GATEWAY__PKI_KEY_FILE} --ca-cert-filepath ${ROOT_CA__PKI_CERT_FILE} --ca-key-filepath ${ROOT_CA__PKI_KEY_FILE} --key-algorithm ${KEYALG_TYPE}:${KEYALG_PARAMS} --subj-common-name ${TRUST0_GATEWAY__PKI_SUBJ_COMMONNAME} --subj-country ${TRUST0_GATEWAY__PKI_SUBJ_COUNTRY} --subj-state ${TRUST0_GATEWAY__PKI_SUBJ_STATE} --subj-city ${TRUST0_GATEWAY__PKI_SUBJ_CITY} --subj-company ${TRUST0_GATEWAY__PKI_SUBJ_COMPANY} --subj-dept ${TRUST0_GATEWAY__PKI_SUBJ_DEPT} --san-dns1 ${TRUST0_GATEWAY__PKI_HOST_DNS1} --san-dns2 ${TRUST0_GATEWAY__PKI_HOST_DNS2}
	@echo ""

gateway-server-pki: generate-root-ca-pki-resources generate-gateway-pki-resources

trust0-gateway:
	${CARGO_CMD} build --color=always --bin trust0-gateway --manifest-path ${PROJECT_DIR}/crates/gateway/Cargo.toml ${CARGOBUILD_EXTRA_ARGS}

run-trust0-gateway: gateway-server-pki trust0-gateway
	${TRUST0_GATEWAY__BINARY_FILE} --port ${TRUST0_GATEWAY__PORT} --cert-file ${TRUST0_GATEWAY__PKI_CERT_FILE} --key-file ${TRUST0_GATEWAY__PKI_KEY_FILE} --auth-cert-file ${ROOT_CA__PKI_CERT_FILE} --gateway-service-host ${TRUST0_GATEWAY__SERVICE_HOST} ${EXECBIN_EXTRA_ARGS} in-memory-db --access-db-file ${DATASOURCE_INMEMDB_ACCESS_FILE} --service-db-file ${DATASOURCE_INMEMDB_SERVICE_FILE} --user-db-file ${DATASOURCE_INMEMDB_USER_FILE}

run-trust0-gateway-nodeps:
	${TRUST0_GATEWAY__BINARY_FILE} --port ${TRUST0_GATEWAY__PORT} --cert-file ${TRUST0_GATEWAY__PKI_CERT_FILE} --key-file ${TRUST0_GATEWAY__PKI_KEY_FILE} --auth-cert-file ${ROOT_CA__PKI_CERT_FILE} --gateway-service-host ${TRUST0_GATEWAY__SERVICE_HOST} ${EXECBIN_EXTRA_ARGS} in-memory-db --access-db-file ${DATASOURCE_INMEMDB_ACCESS_FILE} --service-db-file ${DATASOURCE_INMEMDB_SERVICE_FILE} --user-db-file ${DATASOURCE_INMEMDB_USER_FILE}

# Targets - Trust Client

generate-client-pki-resources: ${EXAMPLE_CONFIG_FILE}
	@echo "Creating client PKI resources"
	@([ '${KEYALG_TYPE}' != '${KEYALG_EC_TYPE}' ] || [ -f ${KEYALG_PARAMS} ] || ${OPENSSL_CMD} ecparam -name ${KEYALG_EC_CURVE} -out ${KEYALG_PARAMS})
	cd ${EXAMPLE_BUILD_DIR} && ${TRUST0_ADMIN_CMD} client-pki-creator --client-cert-filepath ${TRUST0_CLIENT__PKI_CERT_FILE} --client-key-filepath ${TRUST0_CLIENT__PKI_KEY_FILE} --ca-cert-filepath ${ROOT_CA__PKI_CERT_FILE} --ca-key-filepath ${ROOT_CA__PKI_KEY_FILE} --key-algorithm ${KEYALG_TYPE}:${KEYALG_PARAMS} --auth-user-id ${TRUST0_CLIENT__PKI_SUBJ_USERID} --auth-platform ${TRUST0_CLIENT__PKI_SUBJ_PLATFORM} --subj-common-name ${TRUST0_CLIENT__PKI_SUBJ_COMMONNAME} --subj-country ${TRUST0_CLIENT__PKI_SUBJ_COUNTRY} --subj-state ${TRUST0_CLIENT__PKI_SUBJ_STATE} --subj-city ${TRUST0_CLIENT__PKI_SUBJ_CITY} --subj-company ${TRUST0_CLIENT__PKI_SUBJ_COMPANY} --subj-dept ${TRUST0_CLIENT__PKI_SUBJ_DEPT}
	@echo ""

client-pki: generate-root-ca-pki-resources generate-client-pki-resources

trust0-client:
	${CARGO_CMD} build --color=always --bin trust0-client --manifest-path ${PROJECT_DIR}/crates/client/Cargo.toml ${CARGOBUILD_EXTRA_ARGS}

run-trust0-client: trust0-client client-pki
	${TRUST0_CLIENT__BINARY_FILE} --gateway_host ${TRUST0_GATEWAY__HOST} --gateway-port ${TRUST0_GATEWAY__PORT} --auth-key-file ${TRUST0_CLIENT__PKI_KEY_FILE} --auth-cert-file ${TRUST0_CLIENT__PKI_CERT_FILE} --ca-root-cert-file ${ROOT_CA__PKI_CERT_FILE} ${EXECBIN_EXTRA_ARGS}

run-trust0-client-nodeps:
	${TRUST0_CLIENT__BINARY_FILE} --gateway_host ${TRUST0_GATEWAY__HOST} --gateway-port ${TRUST0_GATEWAY__PORT} --auth-key-file ${TRUST0_CLIENT__PKI_KEY_FILE} --auth-cert-file ${TRUST0_CLIENT__PKI_CERT_FILE} --ca-root-cert-file ${ROOT_CA__PKI_CERT_FILE} ${EXECBIN_EXTRA_ARGS}

# Targets - CRL

setup-crl-files: root-ca-pki client-pki
	@echo -n '' > ${ROOT_CA__PKI_DATABASE_FILE}
	@echo '1000' > ${ROOT_CA__PKI_CRLNUMBER_FILE}
	@rm -f ${CRLSUPPORT__PKI_REVOKE_CLIENT_FILE}
	@touch ${CRLSUPPORT__PKI_GATEWAY_CONFIGURED_FILE}
	cd ${TESTDATA_BUILD_DIR} && ${OPENSSL_CMD} ca -config ${ROOT_CA__PKI_CRL_CONF_FILE} -keyfile ${ROOT_CA__PKI_KEY_FILE} -cert ${ROOT_CA__PKI_CERT_FILE} -gencrl -crldays 7 -revoke ${TRUST0_CLIENT__PKI_CERT_FILE} -crl_reason keyCompromise -out ${CRLSUPPORT__PKI_REVOKE_CLIENT_FILE}
	cd ${TESTDATA_BUILD_DIR} && ${OPENSSL_CMD} ca -config ${ROOT_CA__PKI_CRL_CONF_FILE} -keyfile ${ROOT_CA__PKI_KEY_FILE} -cert ${ROOT_CA__PKI_CERT_FILE} -gencrl -crldays 7 -out ${CRLSUPPORT__PKI_REVOKE_CLIENT_FILE}
