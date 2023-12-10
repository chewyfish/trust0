SHELL:=/bin/bash

# Params

TESTDATA_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
TESTDATA_BUILD_DIR=${TESTDATA_DIR}/target
TESTDATA_BUILD_DIRFILE=${TESTDATA_BUILD_DIR}/.marker
OPENSSL_CMD=openssl

# Params - Certificate Authority

ROOT_CA__PKI_NAME=root-ca.local
ROOT_CA__PKI_SUBJ_COMMONNAME=${ROOT_CA__PKI_NAME}
ROOT_CA__PKI_KEY_FILE=${TESTDATA_BUILD_DIR}/${ROOT_CA__PKI_NAME}.key.pem
ROOT_CA__PKI_CERT_FILE=${TESTDATA_BUILD_DIR}/${ROOT_CA__PKI_NAME}.crt.pem
ROOT_CA__PKI_CERT_CONF_FILE=${TESTDATA_BUILD_DIR}/${ROOT_CA__PKI_NAME}.crt.cnf
ROOT_CA__PKI_CRL_CONF_FILE=${TESTDATA_BUILD_DIR}/${ROOT_CA__PKI_NAME}.crl.cnf
ROOT_CA__PKI_DATABASE_FILE=${TESTDATA_BUILD_DIR}/ca-index.txt
ROOT_CA__PKI_CRLNUMBER_FILE=${TESTDATA_BUILD_DIR}/ca-crlnumber.txt

# Params - Client

CLIENT0__PKI_NAME=client0.local
CLIENT0__PKI_SUBJ_COMMONNAME=${CLIENT0__PKI_NAME}
CLIENT0__PKI_KEY_FILE=${TESTDATA_BUILD_DIR}/${CLIENT0__PKI_NAME}.key.pem
CLIENT0__PKI_CSR_FILE=${TESTDATA_BUILD_DIR}/${CLIENT0__PKI_NAME}.csr
CLIENT0__PKI_CERT_FILE=${TESTDATA_BUILD_DIR}/${CLIENT0__PKI_NAME}.crt.pem

CLIENT1__PKI_NAME=client1.local
CLIENT1__PKI_SUBJ_COMMONNAME=${CLIENT1__PKI_NAME}
CLIENT1__PKI_KEY_FILE=${TESTDATA_BUILD_DIR}/${CLIENT1__PKI_NAME}.key.pem
CLIENT1__PKI_CSR_FILE=${TESTDATA_BUILD_DIR}/${CLIENT1__PKI_NAME}.csr
CLIENT1__PKI_CERT_FILE=${TESTDATA_BUILD_DIR}/${CLIENT1__PKI_NAME}.crt.pem

# Params - CRL

CRL_0__PKI_FILE=${TESTDATA_BUILD_DIR}/revoked-crts-0.crl.pem
CRL_1__PKI_FILE=${TESTDATA_BUILD_DIR}/revoked-crts-1.crl.pem
CRL_0_1__PKI_FILE=${TESTDATA_BUILD_DIR}/revoked-crts-0-1.crl.pem

# Targets

.PHONY: default check-prereqs clean-all root-ca-pki client-pki crl-files

default:

clean-all:
	rm -f ${TESTDATA_BUILD_DIR}/*.srl
	rm -f ${ROOT_CA__PKI_KEY_FILE}
	rm -f ${ROOT_CA__PKI_CERT_FILE}
	rm -f ${ROOT_CA__PKI_CERT_CONF_FILE}
	rm -f ${ROOT_CA__PKI_CRL_CONF_FILE}
	rm -f ${ROOT_CA__PKI_DATABASE_FILE}
	rm -f ${ROOT_CA__PKI_CRLNUMBER_FILE}
	rm -f ${CLIENT0__PKI_KEY_FILE}
	rm -f ${CLIENT0__PKI_CSR_FILE}
	rm -f ${CLIENT0__PKI_CERT_FILE}
	rm -f ${CLIENT1__PKI_KEY_FILE}
	rm -f ${CLIENT1__PKI_CSR_FILE}
	rm -f ${CLIENT1__PKI_CERT_FILE}
	rm -f ${CRL_0__PKI_FILE}
	rm -f ${CRL_1__PKI_FILE}
	rm -f ${CRL_0_1__PKI_FILE}

check-prereqs:
	@(which ${OPENSSL_CMD} 2> /dev/null > /dev/null || echo "Command '${OPENSSL_CMD}' missing, please install")

${TESTDATA_BUILD_DIRFILE}:
	@mkdir -p "${TESTDATA_BUILD_DIR}" && touch "$@"

# Targets - ROOT CA

${ROOT_CA__PKI_KEY_FILE}: ${TESTDATA_BUILD_DIRFILE}
	@echo "Creating $@"
	cd ${TESTDATA_BUILD_DIR} && ${OPENSSL_CMD} genrsa -out ${ROOT_CA__PKI_KEY_FILE} 4096
	@echo ""

.ONESHELL:
${ROOT_CA__PKI_CERT_CONF_FILE}: ${TESTDATA_BUILD_DIRFILE}
	@echo "Creating $@"
	cat <<- EOF > $@
		[ v3_ca ]
		subjectKeyIdentifier = hash
		extendedKeyUsage = critical, serverAuth, clientAuth
		basicConstraints = CA:true
		keyUsage = cRLSign, keyCertSign, digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign
		[ v3_client ]
		basicConstraints = critical,CA:false
		keyUsage = nonRepudiation, digitalSignature
		extendedKeyUsage = critical, clientAuth
		subjectKeyIdentifier = hash
		authorityKeyIdentifier = keyid:always,issuer:always
	EOF
	@echo ""

${ROOT_CA__PKI_CERT_FILE}: ${TESTDATA_BUILD_DIRFILE} ${ROOT_CA__PKI_KEY_FILE} ${ROOT_CA__PKI_CERT_CONF_FILE}
	@echo "Creating $@"
	cd ${TESTDATA_BUILD_DIR} && ${OPENSSL_CMD} req -x509 -new -nodes -key ${ROOT_CA__PKI_KEY_FILE} -sha256 -days 3650 -out ${ROOT_CA__PKI_CERT_FILE} -subj "/CN=${ROOT_CA__PKI_SUBJ_COMMONNAME}" -config ${ROOT_CA__PKI_CERT_CONF_FILE} -extensions v3_ca
	@echo ""

.ONESHELL:
${ROOT_CA__PKI_CRL_CONF_FILE}: ${TESTDATA_BUILD_DIRFILE}
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

root-ca-pki: ${ROOT_CA__PKI_CERT_FILE} ${ROOT_CA__PKI_CERT_CONF_FILE} ${ROOT_CA__PKI_CRL_CONF_FILE}
	@echo "Finished root-ca"
	@echo "################"
	@echo ""

# Targets - Client

${CLIENT0__PKI_KEY_FILE}: ${TESTDATA_BUILD_DIRFILE}
	@echo "Creating $@"
	cd ${TESTDATA_BUILD_DIR} && ${OPENSSL_CMD} genrsa -out ${CLIENT0__PKI_KEY_FILE} 4096
	@echo ""

${CLIENT0__PKI_CSR_FILE}: ${TESTDATA_BUILD_DIRFILE} ${CLIENT0__PKI_KEY_FILE}
	@echo "Creating $@"
	cd ${TESTDATA_BUILD_DIR} && ${OPENSSL_CMD} req -key ${CLIENT0__PKI_KEY_FILE} -subj "/CN=${CLIENT0__PKI_SUBJ_COMMONNAME}" -new -out ${CLIENT0__PKI_CSR_FILE}
	@echo ""

${CLIENT0__PKI_CERT_FILE}: ${TESTDATA_BUILD_DIRFILE} ${ROOT_CA__PKI_CERT_FILE} ${ROOT_CA__PKI_KEY_FILE} ${ROOT_CA__PKI_CERT_CONF_FILE} ${CLIENT0__PKI_CSR_FILE}
	@echo "Creating $@"
	cd ${TESTDATA_BUILD_DIR} && ${OPENSSL_CMD} x509 -req -in ${CLIENT0__PKI_CSR_FILE} -out ${CLIENT0__PKI_CERT_FILE} -CA ${ROOT_CA__PKI_CERT_FILE} -CAkey ${ROOT_CA__PKI_KEY_FILE} -sha256 -days 3000 -set_serial 300 -extfile ${ROOT_CA__PKI_CERT_CONF_FILE} -extensions v3_client
	@echo ""

${CLIENT1__PKI_KEY_FILE}: ${TESTDATA_BUILD_DIRFILE}
	@echo "Creating $@"
	cd ${TESTDATA_BUILD_DIR} && ${OPENSSL_CMD} genrsa -out ${CLIENT1__PKI_KEY_FILE} 4096
	@echo ""

${CLIENT1__PKI_CSR_FILE}: ${TESTDATA_BUILD_DIRFILE} ${CLIENT1__PKI_KEY_FILE}
	@echo "Creating $@"
	cd ${TESTDATA_BUILD_DIR} && ${OPENSSL_CMD} req -key ${CLIENT1__PKI_KEY_FILE}  -subj "/CN=${CLIENT1__PKI_SUBJ_COMMONNAME}" -new -out ${CLIENT1__PKI_CSR_FILE}
	@echo ""

${CLIENT1__PKI_CERT_FILE}: ${TESTDATA_BUILD_DIRFILE} ${ROOT_CA__PKI_CERT_FILE} ${ROOT_CA__PKI_KEY_FILE} ${ROOT_CA__PKI_CERT_CONF_FILE} ${CLIENT1__PKI_CSR_FILE}
	@echo "Creating $@"
	cd ${TESTDATA_BUILD_DIR} && ${OPENSSL_CMD} x509 -req -in ${CLIENT1__PKI_CSR_FILE} -out ${CLIENT1__PKI_CERT_FILE} -CA ${ROOT_CA__PKI_CERT_FILE} -CAkey ${ROOT_CA__PKI_KEY_FILE} -sha256 -days 3000 -set_serial 301 -extfile ${ROOT_CA__PKI_CERT_CONF_FILE} -extensions v3_client
	@echo ""

client-pki: root-ca-pki ${CLIENT0__PKI_CERT_FILE} ${CLIENT1__PKI_CERT_FILE}
	@echo "Finished client-pki"
	@echo "#######################"
	@echo ""

# Targets - CRL

crl-files: root-ca-pki client-pki
	@echo -n '' > ${ROOT_CA__PKI_DATABASE_FILE}
	@echo '1000' > ${ROOT_CA__PKI_CRLNUMBER_FILE}
	@rm -f ${CRL_0__PKI_FILE}
	@rm -f ${CRL_1__PKI_FILE}
	@rm -f ${CRL_0_1__PKI_FILE}
	cd ${TESTDATA_BUILD_DIR} && ${OPENSSL_CMD} ca -config ${ROOT_CA__PKI_CRL_CONF_FILE} -keyfile ${ROOT_CA__PKI_KEY_FILE} -cert ${ROOT_CA__PKI_CERT_FILE} -gencrl -crldays 7 -revoke ${CLIENT0__PKI_CERT_FILE} -crl_reason keyCompromise -out ${CRL_0__PKI_FILE}
	cd ${TESTDATA_BUILD_DIR} && ${OPENSSL_CMD} ca -config ${ROOT_CA__PKI_CRL_CONF_FILE} -keyfile ${ROOT_CA__PKI_KEY_FILE} -cert ${ROOT_CA__PKI_CERT_FILE} -gencrl -crldays 7 -out ${CRL_0__PKI_FILE}
	cd ${TESTDATA_BUILD_DIR} && ${OPENSSL_CMD} ca -config ${ROOT_CA__PKI_CRL_CONF_FILE} -keyfile ${ROOT_CA__PKI_KEY_FILE} -cert ${ROOT_CA__PKI_CERT_FILE} -gencrl -crldays 7 -revoke ${CLIENT1__PKI_CERT_FILE} -crl_reason keyCompromise -out ${CRL_1__PKI_FILE}
	cd ${TESTDATA_BUILD_DIR} && ${OPENSSL_CMD} ca -config ${ROOT_CA__PKI_CRL_CONF_FILE} -keyfile ${ROOT_CA__PKI_KEY_FILE} -cert ${ROOT_CA__PKI_CERT_FILE} -gencrl -crldays 7 -out ${CRL_1__PKI_FILE}
	cat ${CRL_0__PKI_FILE} ${CRL_1__PKI_FILE} > ${CRL_0_1__PKI_FILE}
