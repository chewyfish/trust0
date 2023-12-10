SHELL:=/bin/bash

# Params

EXAMPLE_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
EXAMPLE_BUILD_DIR=${EXAMPLE_DIR}/target
EXAMPLE_CONFIG_FILE=${EXAMPLE_BUILD_DIR}/example.conf
PROJECT_DIR=${EXAMPLE_DIR}/..
CARGO_CMD=cargo
OPENSSL_CMD=openssl
M4_CMD=m4
TMUX_CMD=tmux
NCAT_CMD=ncat
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
ROOT_CA__PKI_CERT_CONF_FILE=${EXAMPLE_BUILD_DIR}/${ROOT_CA__PKI_NAME}.cert.cnf
ROOT_CA__PKI_CRL_CONF_FILE=${EXAMPLE_BUILD_DIR}/${ROOT_CA__PKI_NAME}.crl.cnf
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
TRUST0_GATEWAY__PKI_CERT_CONF_FILE=${EXAMPLE_BUILD_DIR}/${TRUST0_GATEWAY__PKI_NAME}.crt.cnf
TRUST0_GATEWAY__PKI_CSR_FILE=${EXAMPLE_BUILD_DIR}/${TRUST0_GATEWAY__PKI_NAME}.csr
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
TRUST0_CLIENT__PKI_CERT_CONF_FILE=${EXAMPLE_BUILD_DIR}/${TRUST0_CLIENT__PKI_NAME}.crt.cnf
TRUST0_CLIENT__PKI_CSR_FILE=${EXAMPLE_BUILD_DIR}/${TRUST0_CLIENT__PKI_NAME}.csr
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

# Targets

.PHONY: default clean-all root-ca-pki gateway-server-pki client-pki trust0-gateway trust0-client run-trust0-gateway run-trust0-client run-trust0-gateway-nodeps run-trust0-client-nodeps setup-crl-files check-prereqs-examples check-prereqs-example-chat-tcp check-prereqs-example-echo-udp check-prereqs-example-revoke-cert

default:

clean-all:
	@rm -f ${EXAMPLE_BUILD_DIR}/*.srl
	@rm -f ${ROOT_CA__PKI_CERT_FILE}
	@rm -f ${ROOT_CA__PKI_KEY_FILE}
	@rm -f ${ROOT_CA__PKI_CERT_CONF_FILE}
	@rm -f ${ROOT_CA__PKI_CRL_CONF_FILE}
	@rm -f ${ROOT_CA__PKI_DATABASE_FILE}
	@rm -f ${ROOT_CA__PKI_DATABASE_FILE}.*
	@rm -f ${ROOT_CA__PKI_CRLNUMBER_FILE}
	@rm -f ${ROOT_CA__PKI_CRLNUMBER_FILE}.*
	@rm -f ${DATASOURCE_INMEMDB_ACCESS_FILE}
	@rm -f ${DATASOURCE_INMEMDB_SERVICE_FILE}
	@rm -f ${DATASOURCE_INMEMDB_USER_FILE}
	@rm -f ${TRUST0_GATEWAY__PKI_CERT_FILE}
	@rm -f ${TRUST0_GATEWAY__PKI_CERT_CONF_FILE}
	@rm -f ${TRUST0_GATEWAY__PKI_CSR_FILE}
	@rm -f ${TRUST0_GATEWAY__PKI_KEY_FILE}
	@rm -f ${TRUST0_CLIENT__PKI_CERT_FILE}
	@rm -f ${TRUST0_CLIENT__PKI_CERT_CONF_FILE}
	@rm -f ${TRUST0_CLIENT__PKI_CSR_FILE}
	@rm -f ${TRUST0_CLIENT__PKI_KEY_FILE}
	@rm -f ${CRLSUPPORT__PKI_GATEWAY_CONFIGURED_FILE}
	@rm -f ${CRLSUPPORT__PKI_REVOKE_CLIENT_FILE}

${EXAMPLE_CONFIG_FILE}:
	@${EXAMPLE_DIR}/run_configure.sh

check-prereqs-examples:
	@(which ${CARGO_CMD} 2> /dev/null > /dev/null || echo "Command '${CARGO_CMD}' missing, please install")
	@(which ${OPENSSL_CMD} 2> /dev/null > /dev/null || echo "Command '${OPENSSL_CMD}' missing, please install")
	@(which ${M4_CMD} 2> /dev/null > /dev/null || echo "Command '${M4_CMD}' missing, please install")
	@(which ${TMUX_CMD} 2> /dev/null > /dev/null || echo "Command '${TMUX_CMD}' missing, please install")
	@(which ${NCAT_CMD} 2> /dev/null > /dev/null || echo "Command '${NCAT_CMD}' missing, please install")

check-prereqs-example-chat-tcp: check-prereqs-examples
check-prereqs-example-echo-udp: check-prereqs-examples
check-prereqs-example-revoke-cert: check-prereqs-examples

# Targets - ROOT CA

${ROOT_CA__PKI_KEY_FILE}: ${EXAMPLE_CONFIG_FILE}
	@echo "Creating $@"
	cd ${EXAMPLE_BUILD_DIR} && ${OPENSSL_CMD} genrsa -out ${ROOT_CA__PKI_KEY_FILE} 4096
	@echo ""

.ONESHELL:
${ROOT_CA__PKI_CERT_CONF_FILE}: ${EXAMPLE_CONFIG_FILE}
	@echo "Creating $@"
	cat <<- EOF > $@
		[ v3_ca ]
		subjectKeyIdentifier = hash
		extendedKeyUsage = critical, serverAuth, clientAuth
		basicConstraints = CA:true
		keyUsage = cRLSign, keyCertSign, digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign
		[ v3_server ]
		subjectKeyIdentifier = hash
		extendedKeyUsage = critical, serverAuth, clientAuth
		basicConstraints = CA:false
		keyUsage = cRLSign, keyCertSign, digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign
		[ v3_client ]
		basicConstraints = critical,CA:false
		keyUsage = nonRepudiation, digitalSignature
		extendedKeyUsage = critical, clientAuth
		subjectKeyIdentifier = hash
		authorityKeyIdentifier = keyid:always,issuer:always
	EOF
	@echo ""

.ONESHELL:
${ROOT_CA__PKI_CRL_CONF_FILE}: ${EXAMPLE_CONFIG_FILE}
	@echo "Creating $@"
	cat <<- EOF > $@
		[ ca ]
		default_ca = ca_default
		[ ca_default ]
		database = ${ROOT_CA__PKI_DATABASE_FILE}
		crlnumber = ${ROOT_CA__PKI_CRLNUMBER_FILE}
		default_md = default
		crl_extensions = crl_ext
		[ crl_ext ]
		authorityKeyIdentifier=keyid:always
	EOF
	@echo ""

${ROOT_CA__PKI_CERT_FILE}: ${EXAMPLE_CONFIG_FILE} ${ROOT_CA__PKI_CERT_CONF_FILE} ${ROOT_CA__PKI_KEY_FILE}
	@echo "Creating $@"
	cd ${EXAMPLE_BUILD_DIR} && ${OPENSSL_CMD} req -x509 -new -nodes -key ${ROOT_CA__PKI_KEY_FILE} -sha256 -days 1826 -out ${ROOT_CA__PKI_CERT_FILE} -subj "/C=${ROOT_CA__PKI_SUBJ_COUNTRY}/ST=${ROOT_CA__PKI_SUBJ_STATE}/L=${ROOT_CA__PKI_SUBJ_CITY}/O=${ROOT_CA__PKI_SUBJ_COMPANY}/OU=${ROOT_CA__PKI_SUBJ_DEPT}/CN=${ROOT_CA__PKI_SUBJ_COMMONNAME}" -config ${ROOT_CA__PKI_CERT_CONF_FILE} -extensions v3_ca
	@echo ""

root-ca-pki: ${ROOT_CA__PKI_CERT_FILE} ${ROOT_CA__PKI_CRL_CONF_FILE}
	@echo "Finished root-ca"
	@echo "################"
	@echo ""

# Targets - Trust Gateway

${TRUST0_GATEWAY__PKI_KEY_FILE}: ${EXAMPLE_CONFIG_FILE}
	@echo "Creating $@"
	cd ${EXAMPLE_BUILD_DIR} && ${OPENSSL_CMD} genrsa -out ${TRUST0_GATEWAY__PKI_KEY_FILE} 2048
	@echo ""

.ONESHELL:
${TRUST0_GATEWAY__PKI_CERT_CONF_FILE}: ${EXAMPLE_CONFIG_FILE}
	@echo "Creating $@"
	cat <<- EOF > $@
		authorityKeyIdentifier=keyid,issuer
		basicConstraints=CA:FALSE
		keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
		extendedKeyUsage = serverAuth
		req_extensions = req_ext
		distinguished_name = req_distinguished_name
		prompt = no
		[ req_ext ]
		subjectAltName = @req_alt_names
		[ req_distinguished_name ]
		C = ${TRUST0_GATEWAY__PKI_SUBJ_COUNTRY}
		ST = ${TRUST0_GATEWAY__PKI_SUBJ_STATE}
		L = ${TRUST0_GATEWAY__PKI_SUBJ_CITY}
		O = ${TRUST0_GATEWAY__PKI_SUBJ_COMPANY}
		OU = ${TRUST0_GATEWAY__PKI_SUBJ_DEPT}
		CN = ${TRUST0_GATEWAY__PKI_SUBJ_COMMONNAME}
		[ req_alt_names ]
		DNS.1 = ${TRUST0_GATEWAY__PKI_HOST_DNS1}
		DNS.2 = ${TRUST0_GATEWAY__PKI_HOST_DNS2}
		IP.1 = ${TRUST0_GATEWAY__PKI_HOST_IP1}
		IP.2 = ${TRUST0_GATEWAY__PKI_HOST_IP2}
	EOF
	@echo ""

${TRUST0_GATEWAY__PKI_CSR_FILE}: ${EXAMPLE_CONFIG_FILE} ${TRUST0_GATEWAY__PKI_KEY_FILE} ${TRUST0_GATEWAY__PKI_CERT_CONF_FILE}
	@echo "Creating $@"
	cd ${EXAMPLE_BUILD_DIR} && ${OPENSSL_CMD} req -key ${TRUST0_GATEWAY__PKI_KEY_FILE} -new -config ${TRUST0_GATEWAY__PKI_CERT_CONF_FILE} -out ${TRUST0_GATEWAY__PKI_CSR_FILE}
	@echo ""

${TRUST0_GATEWAY__PKI_CERT_FILE}: ${EXAMPLE_CONFIG_FILE} ${ROOT_CA__PKI_CERT_FILE} ${ROOT_CA__PKI_KEY_FILE} ${ROOT_CA__PKI_CERT_CONF_FILE} ${TRUST0_GATEWAY__PKI_CSR_FILE}
	@echo "Creating $@"
	cd ${EXAMPLE_BUILD_DIR} && ${OPENSSL_CMD} x509 -req -in ${TRUST0_GATEWAY__PKI_CSR_FILE} -CA ${ROOT_CA__PKI_CERT_FILE} -CAkey ${ROOT_CA__PKI_KEY_FILE} -CAcreateserial -days 365 -copy_extensions copy -extfile ${ROOT_CA__PKI_CERT_CONF_FILE} -extensions v3_server -out ${TRUST0_GATEWAY__PKI_CERT_FILE}
	@echo ""

gateway-server-pki: root-ca-pki ${TRUST0_GATEWAY__PKI_CERT_FILE}
	@echo "Finished gateway-server-pki"
	@echo "###########################"
	@echo ""

trust0-gateway:
	${CARGO_CMD} build --color=always --bin trust0-gateway --manifest-path ${PROJECT_DIR}/crates/gateway/Cargo.toml ${CARGOBUILD_EXTRA_ARGS}

run-trust0-gateway: gateway-server-pki trust0-gateway
	${TRUST0_GATEWAY__BINARY_FILE} --port ${TRUST0_GATEWAY__PORT} --cert-file ${TRUST0_GATEWAY__PKI_CERT_FILE} --key-file ${TRUST0_GATEWAY__PKI_KEY_FILE} --auth-cert-file ${ROOT_CA__PKI_CERT_FILE} --gateway-service-host ${TRUST0_GATEWAY__SERVICE_HOST} ${EXECBIN_EXTRA_ARGS} in-memory-db --access-db-file ${DATASOURCE_INMEMDB_ACCESS_FILE} --service-db-file ${DATASOURCE_INMEMDB_SERVICE_FILE} --user-db-file ${DATASOURCE_INMEMDB_USER_FILE}

run-trust0-gateway-nodeps:
	${TRUST0_GATEWAY__BINARY_FILE} --port ${TRUST0_GATEWAY__PORT} --cert-file ${TRUST0_GATEWAY__PKI_CERT_FILE} --key-file ${TRUST0_GATEWAY__PKI_KEY_FILE} --auth-cert-file ${ROOT_CA__PKI_CERT_FILE} --gateway-service-host ${TRUST0_GATEWAY__SERVICE_HOST} ${EXECBIN_EXTRA_ARGS} in-memory-db --access-db-file ${DATASOURCE_INMEMDB_ACCESS_FILE} --service-db-file ${DATASOURCE_INMEMDB_SERVICE_FILE} --user-db-file ${DATASOURCE_INMEMDB_USER_FILE}

# Targets - Trust Client

${TRUST0_CLIENT__PKI_KEY_FILE}: ${EXAMPLE_CONFIG_FILE}
	@echo "Creating $@"
	cd ${EXAMPLE_BUILD_DIR} && ${OPENSSL_CMD} genrsa -out ${TRUST0_CLIENT__PKI_KEY_FILE} 2048
	@echo ""

.ONESHELL:
${TRUST0_CLIENT__PKI_CERT_CONF_FILE}: ${EXAMPLE_CONFIG_FILE}
	@echo "Creating $@"
	cat <<- EOF > $@
		[ req ]
		default_md = sha256
		basicConstraints = CA:FALSE
		keyUsage = critical, digitalSignature, keyEncipherment
		req_extensions = req_ext
		distinguished_name = req_distinguished_name
		prompt = no
		[ req_ext ]
		subjectAltName = @req_alt_names
		[ req_distinguished_name ]
		C = ${TRUST0_CLIENT__PKI_SUBJ_COUNTRY}
		ST = ${TRUST0_CLIENT__PKI_SUBJ_STATE}
		L = ${TRUST0_CLIENT__PKI_SUBJ_CITY}
		O = ${TRUST0_CLIENT__PKI_SUBJ_COMPANY}
		OU = ${TRUST0_CLIENT__PKI_SUBJ_DEPT}
		CN = ${TRUST0_CLIENT__PKI_SUBJ_COMMONNAME}
		[ req_alt_names ]
		URI = {\"userId\":${TRUST0_CLIENT__PKI_SUBJ_USERID},\"platform\":\"${TRUST0_CLIENT__PKI_SUBJ_PLATFORM}\"}
	EOF
	@echo ""

${TRUST0_CLIENT__PKI_CSR_FILE}: ${EXAMPLE_CONFIG_FILE} ${TRUST0_CLIENT__PKI_KEY_FILE} ${TRUST0_CLIENT__PKI_CERT_CONF_FILE}
	@echo "Creating $@"
	cd ${EXAMPLE_BUILD_DIR} && ${OPENSSL_CMD} req -key ${TRUST0_CLIENT__PKI_KEY_FILE} -new -config ${TRUST0_CLIENT__PKI_CERT_CONF_FILE} -out ${TRUST0_CLIENT__PKI_CSR_FILE}
	@echo ""

${TRUST0_CLIENT__PKI_CERT_FILE}: ${EXAMPLE_CONFIG_FILE} ${ROOT_CA__PKI_CERT_FILE} ${ROOT_CA__PKI_KEY_FILE} ${ROOT_CA__PKI_CERT_CONF_FILE} ${TRUST0_CLIENT__PKI_CSR_FILE}
	@echo "Creating $@"
	cd ${EXAMPLE_BUILD_DIR} && ${OPENSSL_CMD} x509 -req -in ${TRUST0_CLIENT__PKI_CSR_FILE} -CA ${ROOT_CA__PKI_CERT_FILE} -CAkey ${ROOT_CA__PKI_KEY_FILE} -CAcreateserial -days 365 -copy_extensions copy -set_serial 300 -extfile ${ROOT_CA__PKI_CERT_CONF_FILE} -extensions v3_client -out ${TRUST0_CLIENT__PKI_CERT_FILE}
	@echo ""

client-pki: root-ca-pki ${TRUST0_CLIENT__PKI_CERT_FILE}
	@echo "Finished client-pki"
	@echo "#######################"
	@echo ""

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
